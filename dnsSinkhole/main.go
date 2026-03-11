package main

import(
	"fmt"
	"net"
	"os"
	"bufio"
	"strings"
	"golang.org/x/net/dns/dnsmessage"
)

func loadBlacklist(filename string) (map[string]bool, error){
	blacklist := make(map[string]bool)
	fileObj, err := os.Open(filename)
	if err != nil{
		fmt.Printf("error opening blacklist: %v\n", err)
		return nil, err
	}
	defer fileObj.Close()

	scanner := bufio.NewScanner(fileObj)
	for scanner.Scan(){
		currLine := strings.TrimSpace(scanner.Text())
		//skips empty lines and comments in blacklist file
		if currLine == "" || strings.HasPrefix(currLine, "#"){
			continue
		}

		parts := strings.Fields(currLine)
		domain := parts[1]

		if domain != ""{
			blacklist[domain] = true
		}
	}
	fmt.Printf("loaded blacklisted %d domains", len(blacklist))
	return blacklist, nil
}

func getLocalIP() (string){
	conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        fmt.Println("Warning: Could not detect local IP, defaulting to 127.0.0.1")
        return "127.0.0.1"
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP.String()
}

//listens
func main(){
	//first load blacklisted domains
	blacklist, err := loadBlacklist("blacklist.txt")
	if err != nil{
		fmt.Println("error loading blacklist: %v\n", err)
	}

	// fmt.Println("meow %d", len(blacklist))

	hostIP := getLocalIP()
	fmt.Printf("detected local IP\n\n\nATTENTION ATTENTION\nSET DNS PREFERRED IP TO: %s\n\n\n", hostIP)


	//want to listen locally on port 53 through UDP conn
	//struct that combines ip and port
	addr := net.UDPAddr{
		Port: 53,
		//translate string to raw bytes of ip addr
		IP: net.ParseIP(hostIP),
	}

	//routes incoming packets on port 53 to this program
	//conn object allows us to read and write data to network
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil{
		fmt.Println("error listeinign (listening on port 53 usually requires admin privileges): %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("DNS Sinkhole is listening on %s:%d\n", addr.IP, addr.Port)

	//we want a buffer to hold data that is coming in so we can read it for blacklisted domains
	//dns packets are 512 bytes max so buffer is 512 bytes
	buf := make([]byte, 4096)

	for{
		//listens for incoming packets, pauses and waits until a packet arrives
		//get clientaddr to send response to leater
		bytesRead, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil{
			fmt.Println("error reading from UDP: %v\n", err)
			continue
			//continue to listen for other packets even if one has an error
		}
		fmt.Printf("Received DNS query of %d bytes from %s\n", bytesRead, clientAddr)
		
		var msg dnsmessage.Message
		err = msg.Unpack(buf[:bytesRead])
		if err != nil{
			fmt.Printf("error unpacking dns message: %v\n", err)
			continue
		}

		//make sure we have at leats one question to read
		if len(msg.Questions) == 0{
			continue
		}

		domainName := msg.Questions[0].Name.String()
		//dns protocol adds trailing dot to domain name so we want to clean up
		cleanedDomain := strings.TrimSuffix(domainName, ".")
		fmt.Printf("request for domain: %s\n", cleanedDomain)

		//now we check if it is in blacklist
		if blacklist[cleanedDomain]{
			fmt.Printf("domain %s is blacklisted,\n", cleanedDomain)
			//sinkhole req
			//send back a response with a fake answer pointing to sinkhole addr (0.0.0.0)
			msg.Header.Response = true
			msg.Header.Authoritative = true

			sinkResp := dnsmessage.Resource{
				Header:  dnsmessage.ResourceHeader{
					Name: msg.Questions[0].Name,//reply to domain
					Type: dnsmessage.TypeA,//ipv4 address record
					Class: dnsmessage.ClassINET,//internet class
					TTL: 60,
				},
				Body: &dnsmessage.AResource{
					A: [4]byte{0, 0, 0, 0},//sinkhole ip
				},
			}
			msg.Answers = append(msg.Answers, sinkResp)
			packResponse, err := msg.Pack()
			if err != nil{
				fmt.Printf("error packing dns resp %v\n", err)
			}

			_, err = conn.WriteToUDP(packResponse, clientAddr)
			if err != nil{
				fmt.Printf("error sending response: %v\n", err)
			}
		} else{
			fmt.Printf("domain %s is not blacklisted, forwarding request to DNS resolver\n", cleanedDomain)

			//dial connection to a dns server (ucsd dns server is 132.239.0.252 googles is 8.8.8.8)
			dnsConn, err := net.Dial("udp", "8.8.8.8:53")
			if err != nil{
				fmt.Printf("error dialing dns server: %v\n", err)
				continue
			}

			_, err = dnsConn.Write(buf[:bytesRead])
			if err != nil{
				fmt.Printf("error writing to dns server: %v\n", err)
				dnsConn.Close()
				continue
			}

			responseBuf := make([]byte, 4096)
			respBytes, err := dnsConn.Read(responseBuf)
			if err != nil{
				fmt.Printf("error reading from dns server: %v\n", err)
				dnsConn.Close()
				continue
			}

			dnsConn.Close()
			//forward response to client
			_, err = conn.WriteToUDP(responseBuf[:respBytes], clientAddr)
			if err != nil{
				fmt.Printf("error sending response: %v\n", err)
			}
		}
	}
}