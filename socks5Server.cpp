#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
//#include <signal.h>
#pragma pack(1)
#include <thread>
#include <stdlib.h>
#include <mutex>
#include <sstream>
#include <condition_variable>
#include "CJsonObject.hpp"  
#include <fstream>

#define BUF_SIZE  256
using namespace std;
int SERVER_PORT = 9997;
int MAXPENDING = 200;
string USERNAME = "username";
string PASSWORD = "password";

bool ALLOW_NO_AUTH = true;



/* Command constants */
#define CMD_CONNECT         1
#define CMD_BIND            2
#define CMD_UDP_ASSOCIATIVE 3

/* Address type constants */
#define ATYP_IPV4   1
#define ATYP_DNAME  3
#define ATYP_IPV6   4

/* Connection methods */
#define METHOD_NOAUTH       0
#define METHOD_AUTH         2
#define METHOD_NOTAVAILABLE 0xff

/* Responses */
#define RESP_SUCCEDED       0
#define RESP_GEN_ERROR      1


/* Handshake */

struct MethodIdentificationPacket {
	uint8_t version, nmethods;
	/* uint8_t methods[nmethods]; */
};

struct MethodSelectionPacket {
	uint8_t version, method;
	MethodSelectionPacket(uint8_t met) : version(5), method(met) {}
};


/* Requests */

struct SOCKS5RequestHeader {
	uint8_t version, cmd, rsv /* = 0x00 */, atyp;
};

struct SOCK5IP4RequestBody {
	uint32_t ip_dst;
	uint16_t port;
};

struct SOCK5DNameRequestBody {
	uint8_t length;
	/* uint8_t dname[length]; */
};


/* Responses */
struct SOCKS5Response {
	uint8_t version, cmd, rsv /* = 0x00 */, atyp;
	uint32_t ip_src;
	uint16_t port_src;

	SOCKS5Response(bool succeded = true) : version(5), cmd(succeded ? RESP_SUCCEDED : RESP_GEN_ERROR), rsv(0), atyp(ATYP_IPV4) { }
};

mutex get_host_lock;
mutex log_lock;
mutex client_mutex;
condition_variable client_cond;
uint32_t client_count = 0, max_clients = 100;
void do_log(const string &ip)
{
	log_lock.lock();
	ofstream fout("log.txt", ios::app);
	char time[100]{ '/0' };
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(time, "%4d/%02d/%02d %02d:%02d:%02d.%03d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	fout << "Time:" << time;
	fout << "  IP: " << ip << endl;
	fout.close();
	log_lock.unlock();
}

int create_listen_socket()
{
	int serversock;
	sockaddr_in echoserver;
	/* Create the TCP socket */
	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		cout << "[!] COULD NOT CTEATE SOCKET.\n";
		return -1;
	}
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = htonl(INADDR_ANY);   /* Incoming addr */
	echoserver.sin_port = htons(SERVER_PORT);       /* server port */
	/* Bind the server socket */
	if (::bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
		cout << "[!] BIND ERROR.\n";
		return -1;
	}
	/* Listen on the server socket */
	if (listen(serversock, MAXPENDING) < 0) {
		//SOMAXCONN;
		cout << "[!] LISTEN ERROR!\n";
		return -1;
	}
	return serversock;
}
int recv_sock(int sock, char *buffer, uint32_t size) {
	int index = 0, ret;
	while (size) {
		if ((ret = recv(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}

int send_sock(int sock, const char *buffer, uint32_t size) {
	int index = 0, ret;
	while (size) {
		if ((ret = send(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}
int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz) {
	if (recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] > max_sz)
		return false;
	uint8_t sz = buffer[0];
	if (recv_sock(sock, (char*)buffer, sz) != sz)
		return -1;
	return sz;
}
bool check_auth(int sock) {
	string username, password;
	uint8_t buffer[128];
	int sz;
	if (recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] != 1)
		goto Unresolved;
	sz = read_variable_string(sock, buffer, 127);
	if (sz == -1)
		goto Unresolved;
	buffer[sz] = 0;
	username = string((char*)buffer, sz);
	if (username != USERNAME)
		goto wrongusername;
	sz = read_variable_string(sock, buffer, 127);
	if (sz == -1)
		goto Unresolved;
	buffer[sz] = 0;
	password = string((char*)buffer, sz);
	if (password != PASSWORD)
		goto wrongpassword;
	buffer[0] = 1;
	buffer[1] = 0;
	return send_sock(sock, (const char*)buffer, 2) == 2;
wrongpassword:
	cout << "[!] PASSWORD: " << password << endl;
wrongusername:
	cout << "[!] USERNAME: " << username << endl;
	buffer[1] = 1;
	send_sock(sock, (const char*)buffer, 2);
Unresolved:
	return false;
}
void set_fds(int sock1, int sock2, fd_set *fds) {
	FD_ZERO(fds);
	FD_SET(sock1, fds);
	FD_SET(sock2, fds);
}
void do_proxy(int client, int conn) {
	char buffer[BUF_SIZE + 1] = {'/0'};
	fd_set readfds;
	int result, nfds = max(client, conn) + 1;
	set_fds(client, conn, &readfds);
	while ((result = select(nfds, &readfds, 0, 0, 0)) > 0) {
		if (FD_ISSET(client, &readfds)) {
			int recvd = recv(client, buffer, BUF_SIZE, 0);
			if (recvd <= 0)
			{
				if (recvd == 0)
					cout << "[-] proxy finished!\n";
				else
					cout << "[!] PROXY FAILED FROM CLIENT.ERROR CODE: " << WSAGetLastError() << endl;
				return;
			}
			send_sock(conn, buffer, recvd);
			//cout << "[-] Forwarded data: " << strlen(buffer) <<" Byte."<< endl;
		}
		if (FD_ISSET(conn, &readfds)) {
			int recvd = recv(conn, buffer, BUF_SIZE, 0);
			if (recvd <= 0)
			{
				if (recvd == 0)
					cout << "[-] proxy finished!\n";
				else
					cout << "[!] PROXY FAILED FROM SERVER.ERROR CODE: " << WSAGetLastError() << endl;
				return;
			}
			send_sock(client, buffer, recvd);
			//cout << "[-] Retrieved data: " << strlen(buffer) << " Byte." << endl;
		}
		set_fds(client, conn, &readfds);
	}
}
bool handle_handshake(int sock) {
	char buffer[512];
	MethodIdentificationPacket packet;
	MethodSelectionPacket response(METHOD_NOTAVAILABLE);
	int read_size = recv_sock(sock, (char*)&packet, sizeof(MethodIdentificationPacket));
	if (read_size != sizeof(MethodIdentificationPacket) || packet.version != 5)
		goto Unresolved;

	//cout << __LINE__<< "\n";
	if (recv_sock(sock, buffer, packet.nmethods) != packet.nmethods)
		goto Unresolved;
	
	for (unsigned i(0); i < packet.nmethods; ++i) {
		if (ALLOW_NO_AUTH && buffer[i] == METHOD_NOAUTH)
			response.method = METHOD_NOAUTH;
		if (buffer[i] == METHOD_AUTH)
			response.method = METHOD_AUTH;
	}
	if (send_sock(sock, (const char*)&response, sizeof(MethodSelectionPacket)) != sizeof(MethodSelectionPacket))
		goto Unresolved;
	if (response.method == METHOD_NOTAVAILABLE)
		goto methodNotAviliable;
	cout << "[-] method: " << (response.method == METHOD_AUTH ? "METHOD_AUTH" : "METHOD_NOTAVAILABLE") << "\n";
	return (response.method == METHOD_AUTH) ? check_auth(sock) : true;
methodNotAviliable:
	cout << "[!] METHOD_NOTAVAILABLE.\n";
Unresolved:
	return false;
}
string int_to_str(uint32_t ip) {
	ostringstream oss;
	for (unsigned i = 0; i < 4; i++) {
		oss << ((ip >> (i * 8)) & 0xFF);
		if (i != 3)
			oss << '.';
	}
	return oss.str();
}

int connect_to_host(uint32_t ip, uint16_t port) {
	struct sockaddr_in serv_addr;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -1;
	memset((char *)&serv_addr,0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy( (char *)&serv_addr.sin_addr.s_addr,(char *)&ip, sizeof(ip));

	serv_addr.sin_port = htons(port);
	return !connect(sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) ? sockfd : -1;
}
bool handle_request(int sock) {
	SOCKS5RequestHeader header;
	recv_sock(sock, (char*)&header, sizeof(SOCKS5RequestHeader));
	if (header.version != 5 || header.cmd != CMD_CONNECT || header.rsv != 0)
		return false;
	int client_sock = -1;
	SOCK5IP4RequestBody req;
	switch (header.atyp) {
	case ATYP_IPV4:
	{
		cout << "[-] protocol Type: ATYP_IPV4\n";
		if (recv_sock(sock, (char*)&req, sizeof(SOCK5IP4RequestBody)) != sizeof(SOCK5IP4RequestBody))
			return false;
		break;
	}
	case ATYP_DNAME:
	{	
		cout << "[-] protocol Type: ATYP_DNAME\n";
		char buffer[128] = {'/0'};
		int sz = read_variable_string(sock, (uint8_t* )buffer, 127);
		if (sz == -1)
			return false;
		struct hostent *remoteHost;
		struct in_addr addr;
		int i = 0;
		get_host_lock.lock();
		remoteHost = gethostbyname(buffer);
		if (remoteHost == NULL)
		{
			get_host_lock.unlock();
			cout << "[!] UNRESOLVED DOMAIN NAME!\n";
			return false;
		}
		get_host_lock.unlock();
		switch (remoteHost->h_addrtype) {
		case AF_INET:
			addr.s_addr = req.ip_dst = *(u_long *)remoteHost->h_addr_list[0];
			//inet_ntoa(addr);
			break;
		default:
		{
			cout << "[!] UNSUPPORTED PROTOCOL TYPE!\n";
			return false;
		}
		}
		 
		if (recv_sock(sock, (char*)&(req.port), sizeof(req.port)) != sizeof(req.port))
			return false;
		break;
	}
	default:
		return false;
	}
	client_sock = connect_to_host(req.ip_dst, ntohs(req.port));
	if (client_sock == -1)
		return false;
	int_to_str(req.ip_dst);
	cout << "[-] connection established on IP: " << int_to_str(req.ip_dst) << endl;
	SOCKS5Response response;
	response.ip_src = 0;
	response.port_src = SERVER_PORT;
	send_sock(sock, (const char*)&response, sizeof(SOCKS5Response));
	do_proxy(client_sock, sock);
	shutdown(client_sock, SD_SEND);
	closesocket(client_sock);
	return true;
}

void handle_connection(void *arg) {
	int clientsock = (uint64_t)arg;
	
	if (handle_handshake(clientsock))
	{
		cout << "[-] handshake succeed.\n";
		handle_request(clientsock);
	}
		
	shutdown(clientsock, SD_SEND);
	closesocket(clientsock);

	{
		unique_lock<mutex> client_lock(client_mutex);
		client_count--;
		if (client_count == max_clients - 1)
			client_cond.notify_all();
	}

	cout << "[-] one thread finished "  <<endl;
}
int main(int argc, char *argv[]) {
	ifstream fin("config.txt", ios::in);
	if (!fin)
	{
		cout << "[!] LOAD CONFIG FILE FAILED!\n";
	}
	fin.seekg(0, ios_base::end);
	int size = fin.tellg();
	char *buff = new char[size+1]();
	fin.seekg(0, ios_base::beg);
	fin.read(buff, size);
	string configData(buff);
	neb::CJsonObject cj(configData);
	cj.Get("username", USERNAME);
	cj.Get("password", PASSWORD);
	cj.Get("port", SERVER_PORT);
	cj.Get("ALLOW_NO_AUTH", ALLOW_NO_AUTH);
	//cj.Get("maxpending", MAXPENDING);
	cj.Get("maxthread", max_clients);
	delete[] buff;
	fin.close();
	cout << "[-] username: " << USERNAME << endl;
	cout << "[-] password: " << PASSWORD << endl;
	cout << "[-] port: " << SERVER_PORT << endl;
	cout << "[-] maxthread: " << max_clients << endl;
	cout << "[-] allow_no_auth: " << ALLOW_NO_AUTH << endl;
	
	WSADATA wsaData;
	int iResult;
	DWORD dwError;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	
	int listen_sock = create_listen_socket();
	if (listen_sock == -1) {
		cout << "[!] FAILED TO CREATE LINSTEN SOCKET\n";
		return 1;
	}
	//signal(SIGPIPE, sig_handler);
	struct sockaddr_in echoclient;
	int clientlen = sizeof(echoclient);
	int clientsock;
	while (true) {	
		char clientIp[INET_ADDRSTRLEN];
		if ((clientsock = accept(listen_sock, (struct sockaddr *) &echoclient, &clientlen)) > 0) {
			inet_ntop(AF_INET, &echoclient.sin_addr, clientIp, sizeof(clientIp));
			cout << "\n[-] accept one connection.IP: " << clientIp << "  port: " << echoclient.sin_port << endl;
			//do_log(clientIp);
			{
				unique_lock<mutex> client_lock(client_mutex);
				if (client_count == max_clients)
					client_cond.wait(client_lock);
				client_count++;
				thread _thread(handle_connection, (void*)clientsock);
				_thread.detach();
			}
		}
		else
		{
			cout << "[!] ERROR OCCURRED WHEN ACCEPTING!\n";
			break;
		}
	}
	WSACleanup();
	return 0;
}
