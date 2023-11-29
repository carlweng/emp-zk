#ifndef MPFSS_REG_FP_H__
#define MPFSS_REG_FP_H__

#include <set>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "vole/utility.h"
#include "vole/spfss_sender.h"
#include "vole/spfss_recver.h"

using namespace emp;

template<typename IO>
class MpfssRegFp {
public:
	int party;
	int threads;
	int item_n, idx_max, m;
	int tree_height, leave_n;
	int tree_n;
	bool is_malicious;

	PRG prg;
	IO *netio;
	IO **ios;
	__uint128_t secret_share_x;
	ThreadPool *pool;
	std::vector<uint32_t> item_pos_recver;

	MpfssRegFp(int party, int threads, int n, int t, int log_bin_sz, ThreadPool * pool, IO** ios) {
		this->party = party;
		this->threads = threads;
		this->netio = ios[0];
		this->ios = ios;

		this->pool = pool;
		this->is_malicious = false;

		// make sure n = t * leave_n
		this->item_n = t;
		this->idx_max = n;
		this->tree_height = log_bin_sz+1;
		this->leave_n = 1<<(this->tree_height-1);
		this->tree_n = this->item_n;
	}

	~MpfssRegFp() {

	}

	void set_malicious() {
		is_malicious = true;
	}

	void sender_init(__uint128_t delta) {
		secret_share_x = delta;
	}

	void recver_init() {
		item_pos_recver.resize(this->item_n);
	}

	void set_vec_x(__uint128_t *out, __uint128_t *in) {
		for(int i = 0; i < tree_n; ++i) {
			int pt = i*leave_n+(item_pos_recver[i]%leave_n);
			out[pt] = out[pt] ^ (__uint128_t)makeBlock(in[i], 0x0LL);
		}
	}

	void mpfss(uint64_t *sparse_vector, uint64_t *triple_yz, OTPre<IO> *ot) {
	    uint64_t *check_VW_buf = new uint64_t[item_n];
		vector<SpfssSenderFp<IO>*> senders;
		vector<future<void>> fut;
		for(int i = 0; i < tree_n; ++i) {
            senders.push_back(new SpfssSenderFp<IO>(netio, tree_height));
		    ot->choices_sender();
		}
		netio->flush();
		ot->reset();

		uint32_t width = tree_n / threads;
		uint32_t start = 0, end = width;
		for(int i = 0; i < threads - 1; ++i) {
			fut.push_back(pool->enqueue([this, start, end, width, senders, ot, sparse_vector, triple_yz](){
				for (auto i = start; i < end; ++i) {
                    senders[i]->compute(sparse_vector+i*leave_n, secret_share_x, triple_yz[i]);
                    senders[i]->template send<OTPre<IO>>(ot, ios[start/width], i);
                    ios[start/width]->flush();
				}
			}));
			start = end;
			end += width;
		}
		end = tree_n;
		for (auto i = start; i < end; ++i) {
            senders[i]->compute(sparse_vector+i*leave_n, secret_share_x, triple_yz[i]);
            senders[i]->template send<OTPre<IO>>(ot, ios[threads-1], i);
            ios[threads-1]->flush();
		}
		for (auto & f : fut) f.get();

		if(is_malicious) {
			block *seed = new block[threads];
			seed_expand(seed, threads);
			vector<future<void>> fut;
			uint32_t start = 0, end = width;
			for(int i = 0; i < threads - 1; ++i) {
				fut.push_back(pool->enqueue([this, start, end, width, senders, seed, check_VW_buf](){
					for (auto i = start; i < end; ++i) {
						senders[i]->consistency_check_msg_gen(check_VW_buf[i], ios[start/width], seed[start/width]);
					}
				}));
				start = end;
				end += width;
			}
			end = tree_n;
			for (auto i = start; i < end; ++i) {
				senders[i]->consistency_check_msg_gen(check_VW_buf[i], ios[threads-1], seed[threads-1]);
			}
			for (auto & f : fut) f.get();
			delete[] seed;
		}

		if(is_malicious) {
			consistency_batch_check(check_VW_buf, triple_yz[tree_n], tree_n);
		}

		for (auto p : senders) delete p;
		delete[] check_VW_buf;
	}

	void mpfss(__uint128_t * sparse_vector, __uint128_t *triple_yz, OTPre<IO> *ot) {
	    __uint128_t *check_chialpha_buf = new __uint128_t[item_n];
        __uint128_t *check_VW_buf = new __uint128_t[item_n];

		vector<SpfssRecverFp<IO>*> recvers;
		vector<future<void>> fut;
		for(int i = 0; i < tree_n; ++i) {
            recvers.push_back(new SpfssRecverFp<IO>(netio, tree_height));
            ot->choices_recver(recvers[i]->b);
            item_pos_recver[i] = recvers[i]->get_index();
		}
		netio->flush();
		ot->reset();

		uint32_t width = tree_n / threads;
		uint32_t start = 0, end = width;
		for(int i = 0; i < threads - 1; ++i) {
			fut.push_back(pool->enqueue([this, start, end, width, recvers, ot, sparse_vector, triple_yz](){
				for (auto i = start; i < end; ++i) {
                    recvers[i]->template recv<OTPre<IO>>(ot, ios[start/width], i);
                    recvers[i]->compute(sparse_vector+i*leave_n, triple_yz[i]);
                    ios[start/width]->flush();
				}
			}));
			start = end;
			end += width;
		}
		end = tree_n;
		for (auto i = start; i < end; ++i) {
            recvers[i]->template recv<OTPre<IO>>(ot, ios[threads-1], i);
            recvers[i]->compute(sparse_vector+i*leave_n, triple_yz[i]);
            ios[threads-1]->flush();
		}
		for (auto & f : fut) f.get();

		if(is_malicious) {
			block *seed = new block[threads];
			seed_expand(seed, threads);
			vector<future<void>> fut;
			uint32_t start = 0, end = width;
			for(int i = 0; i < threads - 1; ++i) {
				fut.push_back(pool->enqueue([this, start, end, width, recvers, seed, triple_yz, check_chialpha_buf, check_VW_buf](){
					for (auto i = start; i < end; ++i) {
						recvers[i]->consistency_check_msg_gen(check_chialpha_buf[i], check_VW_buf[i], ios[start/width], triple_yz[i], seed[start/width]);
					}
				}));
				start = end;
				end += width;
			}
			end = tree_n;
			for (auto i = start; i < end; ++i) {
				recvers[i]->consistency_check_msg_gen(check_chialpha_buf[i], check_VW_buf[i], ios[threads-1], triple_yz[i], seed[threads-1]);
			}
			for (auto & f : fut) f.get();
			delete[] seed;
		}

		if(is_malicious) {
			consistency_batch_check(check_chialpha_buf, check_VW_buf,
                    triple_yz, triple_yz[tree_n], tree_n);
		}

		for (auto p : recvers) delete p;
		delete[] check_chialpha_buf;
		delete[] check_VW_buf;
	}

	void seed_expand(block *seed, int threads) {
		block sd = zero_block;
		if(party == ALICE) {
			netio->recv_data(&sd, sizeof(block));
		} else {
			prg.random_block(&sd, 1);
			netio->send_data(&sd, sizeof(block));
			netio->flush();
		}
		PRG prg2(&sd);
		prg2.random_block(seed, threads);
	}

	void consistency_batch_check(uint64_t *check_VW_buf, uint64_t y, int num) {
		uint64_t x_star;
		netio->recv_data(&x_star, sizeof(uint64_t));
		uint64_t tmp = mult_mod(secret_share_x, x_star);
		tmp = add_mod(y, tmp);
		uint64_t vb = PR - tmp;	// y_star

		for(int i = 0; i < num; ++i)
			vb = add_mod(vb, check_VW_buf[i]);
		Hash hash;
		block h = hash.hash_for_block(&vb, sizeof(uint64_t));
		netio->send_data(&h, sizeof(block));
		netio->flush();
	}

	void consistency_batch_check(__uint128_t *check_chialpha_buf,
            __uint128_t *check_VW_buf,
            __uint128_t *delta2, __uint128_t z, int num) {
		uint64_t beta_mul_chialpha = (uint64_t)0;
		for(int i = 0; i < num; ++i) {
			uint64_t tmp = mult_mod(_mm_extract_epi64((block)delta2[i], 1), check_chialpha_buf[i]);
			beta_mul_chialpha = add_mod(beta_mul_chialpha, tmp);
		}
		uint64_t x_star = PR - beta_mul_chialpha;
		x_star = add_mod(_mm_extract_epi64((block)z, 1), x_star);
		netio->send_data(&x_star, sizeof(uint64_t));
		netio->flush();

		uint64_t va = PR - _mm_extract_epi64((block)z, 0);
		for(int i = 0; i < num; ++i)
			va = add_mod(va, (uint64_t)check_VW_buf[i]);

		Hash hash;
		block h = hash.hash_for_block(&va, sizeof(uint64_t));
		block r;
		netio->recv_data(&r, sizeof(block));
		if(!cmpBlock(&r, &h, 1)) error("MPFSS batch check fails");
	}

	// debug
	void check_correctness(IO *io2, __uint128_t* vector, __uint128_t gamma, __uint128_t y) {
		io2->send_data(vector, leave_n*sizeof(__uint128_t));
		io2->send_data(&gamma, sizeof(__uint128_t));
		io2->send_data(&secret_share_x, sizeof(__uint128_t));

		io2->send_data(&y, sizeof(__uint128_t));
	}

	// debug
	void check_correctness(IO *io2, __uint128_t *vector, __uint128_t beta, __uint128_t delta2, int pos, __uint128_t x, __uint128_t z) {
		__uint128_t *sendervec = new __uint128_t[leave_n];
		__uint128_t gamma, delta, y;
		io2->recv_data(sendervec, leave_n*sizeof(__uint128_t));
		io2->recv_data(&gamma, sizeof(__uint128_t));
		io2->recv_data(&delta, sizeof(__uint128_t));
		__uint128_t delta3 = delta;
		io2->recv_data(&y, sizeof(__uint128_t));

		for(int i = 0; i < leave_n; ++i) {
			if(i == pos)
				continue;
			if(vector[i] != sendervec[i]) {
				std::cout << "wrong node at: "<<  i << " " << (uint64_t)vector[i] << " " << (uint64_t)sendervec[i] << std::endl;
				abort();
			}
		}

		delta = mod(delta*beta, pr);
		delta = mod(delta+sendervec[pos], pr);
		if(delta != vector[pos]) {
			std::cout << "wrong secret" << std::endl;
			abort();
		}
		else std::cout << "right vector" << std::endl;
		
		delta3 = mod(delta3*x, pr);
		delta3 = mod(delta3+y, pr);
		if(delta3 != z) {
			std::cout << "wrong triple" << std::endl;
			abort();
		} else std::cout << "right check triple" << std::endl;
	}


};
#endif
