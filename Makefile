all: ssltest

ssltest: ssltest.cpp Makefile
	g++ ssltest.cpp -I/home/neunhoef/include -L/home/neunhoef/lib -Wall -std=c++17 -o ssltest -g -O0 /home/neunhoef/lib/libssl.a /home/neunhoef/lib/libcrypto.a -ldl -lpthread
	#g++ ssltest.cpp -Wall -std=c++17 -o ssltest -g -O0 -lssl -lcrypto

