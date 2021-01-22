all: client server 
#http-client

clean:
	rm client server

client: client.c server.h
	gcc -Wall -g -o client client.c -I. -I../libwebsockets/include -L../libwebsockets/lib -lwebsockets -lpthread -Wl,-rpath,../libwebsockets/lib

server: server.c server.h
	gcc -Wall -g -o server server.c -I. -I../libwebsockets/include -L../libwebsockets/lib -lwebsockets -Wl,-rpath,../libwebsockets/lib

http-client: http-client.c server.h
	gcc -Wall -g -o http-client http-client.c -lcurl -I.
