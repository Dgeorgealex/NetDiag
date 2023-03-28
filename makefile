all:
	g++ server.cpp -o server
	g++ client.cpp -o client -lncurses
clean:
	rm -f client server