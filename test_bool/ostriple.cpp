#include "emp-tool/emp-tool.h"
#include "emp-zk-bool/emp-zk-bool.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

void test_auth_bit_input(OSTriple<NetIO> *os, NetIO *io) {
	PRG prg;
	int len = 1024;
	block *auth = new block[len];
	bool *in = new bool[len];
	if(party == ALICE) {
		PRG prg;
		prg.random_bool(in, len);
		os->authenticated_bits_input(auth, in, len);
		os->check_auth_mac(auth, in, len, io);
	} else {
		os->authenticated_bits_input(auth, in, len);
		os->check_auth_mac(auth, in, len, io);
	}
	delete[] auth;
	delete[] in;
}

void test_compute_and_gate_check(OSTriple<NetIO> *os, NetIO *io) {
	PRG prg;
	int len = 1024;
	block *a = new block[3*len];
	bool *ain = new bool[3*len];
	if(party == ALICE) {
		prg.random_bool(ain, 2*len);
	}
	os->authenticated_bits_input(a, ain, 2*len);
	os->check_auth_mac(a, ain, 2*len, io);
	std::cout << "generate triple inputs" << std::endl;
	for(int i = 0; i < len; ++i) {
		a[2*len+i] = os->auth_compute_and(a[i], a[len+i]);
		ain[2*len+i] = getLSB(a[2*len+i]);
	}
	std::cout << "compute AND" << std::endl;
	os->check_auth_mac(a+2*len, ain+2*len, len, io);

	os->check_compute_and(a, a+len, a+2*len, len, io);
	std::cout << "check for computing AND gate\n";

	std::cout << "number of triples computed in buffer: " << os->andgate_cnt << std::endl;

	delete[] a;
	delete[] ain;
}
void test_ostriple(NetIO *ios[threads+1], int party) {
	auto t1 = clock_start();
	OSTriple<NetIO> os(party, threads, ios);
	cout <<party<<"\tconstructor\t"<< time_from(t1)<<" us"<<endl;

	test_auth_bit_input(&os, ios[threads]);
	std::cout << "check for authenticated bit input\n";

	test_compute_and_gate_check(&os, ios[threads]);

	std::cout << std::endl;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads+1];
	for(int i = 0; i < threads+1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

	std::cout << std::endl << "------------ triple generation test ------------" << std::endl << std::endl;;

	test_ostriple(ios, party);

	for(int i = 0; i < threads+1; ++i)
		delete ios[i];
	return 0;
}