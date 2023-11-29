#ifndef COPE_H__
#define COPE_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "vole/utility.h"

template<typename IO>
class Cope {
public:
	int party;
	int m;
	IO *io;
	block *K = nullptr;
	uint64_t delta;
	PRG *G0 = nullptr, *G1 = nullptr;
	bool *delta_bool = nullptr;

	Cope(int party, IO *io, int m) {
		this->party = party;
		this->m = m;
		this->io = io;
	}

	~Cope() {
		if(G0 != nullptr) delete[] G0;
		if(G1 != nullptr) delete[] G1;
		if(delta_bool != nullptr) delete[] delta_bool;
	}

	// sender
	void initialize(uint64_t delta) {
		this->delta = delta;
		delta_bool = new bool[m];
		delta64_to_bool(delta_bool, delta);

		K = new block[m];
		OTCO<IO> otco(io);
		otco.recv(K, delta_bool, m);

		G0 = new PRG[m];
		for(int i = 0; i < m; ++i)
			G0[i].reseed(K+i);

		delete[] K;
	}

	// recver
	void initialize() {
		K = new block[2*m];
		PRG prg;
		prg.random_block(K, 2*m);
		OTCO<IO> otco(io);
		otco.send(K, K+m, m);

		G0 = new PRG[m];
		G1 = new PRG[m];
		for(int i = 0; i < m; ++i) {
			G0[i].reseed(K+i);
			G1[i].reseed(K+m+i);
		}

		delete[] K;
	}

	// sender
	uint64_t extend() {
        block buf;
		uint64_t *w = new uint64_t[m];
		uint64_t *v = new uint64_t[m];
		for(int i = 0; i < m; ++i) {
			G0[i].random_block(&buf, 1);
			w[i] = _mm_extract_epi64(buf, 0);
		}

		io->recv_data(v, m*sizeof(uint64_t));
		uint64_t ch[2];
		ch[0] = 0ULL;
		for(int i = 0; i < m; ++i) {
			ch[1] = v[i];
			v[i] = add_mod(w[i], ch[delta_bool[i]]);
		}

        uint64_t ret = prm2pr(v);

        delete[] w;
        delete[] v;

		return ret;
	}

	// sender batch
	void extend(uint64_t *ret, int size) {
		uint64_t *w = new uint64_t[m*size];
		uint64_t *v = new uint64_t[m*size];
		for(int i = 0; i < m; ++i) {
			G0[i].random_data(&w[i*size], size*sizeof(uint64_t));
			for(int j = 0; j < size; ++j) {
				w[i*size+j] = mod(w[i*size+j]);
			}
		}

		uint64_t ch[2];
		ch[0] = (uint64_t)0;
		for(int i = 0; i < m; ++i) {
			for(int j = 0; j < size; ++j) {
				io->recv_data(&v[i*size+j], sizeof(uint64_t));
				ch[1] = v[i*size+j];
				v[i*size+j] = add_mod(w[i*size+j], ch[delta_bool[i]]);
			}
		}

		prm2pr(ret, v, size);

		delete[] w;
		delete[] v;
	}

	// recver
	uint64_t extend(uint64_t u) {
        block buf[2];
		uint64_t *w0 = new uint64_t[m];
		uint64_t *w1 = new uint64_t[m];
		uint64_t *tau = new uint64_t[m];
		for(int i = 0; i < m; ++i) {
			G0[i].random_block(buf, 1);
			G1[i].random_block(buf+1, 1);
            w0[i] = _mm_extract_epi64(buf[0], 0);
            w1[i] = _mm_extract_epi64(buf[1], 0);
			w1[i] = add_mod(w1[i], u);
			w1[i] = PR - w1[i];
			tau[i] = add_mod(w0[i], w1[i]);
		}

		io->send_data(tau, m*sizeof(uint64_t));
		io->flush();

        uint64_t ret = prm2pr(w0);

        delete[] w0;
        delete[] w1;
        delete[] tau;
		
		return ret;
	}
	
	// recver batch
	void extend(uint64_t *ret, uint64_t *u, int size) {
		uint64_t *w0 = new uint64_t[m*size];
		uint64_t *w1 = new uint64_t[m*size];
		for(int i = 0; i < m; ++i) {
			G0[i].random_data(&w0[i*size], size*sizeof(uint64_t));
			G1[i].random_data(&w1[i*size], size*sizeof(uint64_t));
			for(int j = 0; j < size; ++j) {
				w0[i*size+j] = mod(w0[i*size+j]);
				w1[i*size+j] = mod(w1[i*size+j]);
				
				w1[i*size+j] = add_mod(w1[i*size+j], u[j]);
				w1[i*size+j] = PR - w1[i*size+j];
				uint64_t tau = add_mod(w0[i*size+j], w1[i*size+j]);
				io->send_data(&tau, sizeof(uint64_t));
	//			io->flush();
			}
		}

		prm2pr(ret, w0, size);

		delete[] w0;
		delete[] w1;
	}

	void delta64_to_bool(bool *bdata, uint64_t in) {
		for(int i = 0; i < m; ++i) {
			bdata[i] = ((in & 0x1LL) == 1);
			in >>= 1;
		}
	}

	__uint128_t prm2pr(__uint128_t *a) {
		__uint128_t ret = (__uint128_t)0;
		__uint128_t tmp;
		for(int i = 0; i < m; ++i) {
			tmp = mod(a[i]<<i, pr);
			ret = mod(ret+tmp, pr);
		}
		return ret;
	}
	
	void prm2pr(__uint128_t *ret, __uint128_t *a, int size) {
		memset(ret, 0, size*sizeof(__uint128_t));
		__uint128_t tmp;
		for(int i = 0; i < m; ++i) {
			for(int j = 0; j < size; ++j) {
				tmp = mod(a[i*size+j]<<i, pr);
				ret[j] = mod(ret[j] + tmp, pr);
			}
		}
	}

	void prm2pr(uint64_t *ret, uint64_t *a, int size) {
		memset(ret, 0, size*sizeof(uint64_t));
		uint64_t tmp;
		for(int i = 0; i < m; ++i) {
			for(int j = 0; j < size; ++j) {
				tmp = a[i*size+j];
				tmp = mult_mod(tmp, 1ULL<<i);
				ret[j] = add_mod(ret[j], tmp);
			}
		}
	}

	// debug function
	void check_triple(uint64_t *a, uint64_t *b, int sz) {
		if(party == ALICE) {
			io->send_data(a, sizeof(uint64_t));
			io->send_data(b, sz*sizeof(uint64_t));
		} else {
			uint64_t delta;
			uint64_t *c = new uint64_t[sz];
			io->recv_data(&delta, sizeof(uint64_t));
			io->recv_data(c, sz*sizeof(uint64_t));
			for(int i = 0; i < sz; ++i) {
				uint64_t tmp = mult_mod(a[i], delta);
				tmp = add_mod(tmp, c[i]);
				if(tmp != b[i]) {
					std::cout << "wrong triple" << i<<std::endl;
					abort();
				}
			}
		}
		std::cout << "pass check" << std::endl;
	}
};

#endif
