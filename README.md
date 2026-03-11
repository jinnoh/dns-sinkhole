# dns-sinkhole
To run on linux systems do the following
```
go get golang.org/x/net/dns/dnsmessage
sudo go run dnsSinkhole/main.go
```

On Windows, go to Settings -> Network & internet -> Wi-Fi -> Click on current network -> DNS Server Assignment -> Edit -> Manual -> IPv4 set to On -> Preferred DNS set to the IP given when running the code
