package main

import{
	"fmt"
	"net"
	"os"
}

//listens
func main(){
	//want to listen locally on port 53 through UDP conn
	//struct that combines ip and port
	addr := net.UDPAddr{
		Port: 53,
		//translate string to raw bytes of ip addr
		IP: net.ParseIP("127.0.0.1"),
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
	buf := make([]byte, 512)

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
	}
}