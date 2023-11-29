#ifndef _VOLE_TRIPLE_H_
#define _VOLE_TRIPLE_H_
#include "vole/mpfss_reg.h"
#include "vole/base_svole.h"
#include "vole/lpn.h"
#include "vole/constants.h"

template<typename IO>
class VoleTriple { 
public:
	IO * io;
	IO **ios;
	int party;
	int threads;
	int n, t, k, log_bin_sz;
	int noise_type;
	int M;
	int ot_used, ot_limit;
	bool is_malicious;
	bool extend_initialized;
	bool pre_ot_inplace;
	uint64_t *pre_yz_a = nullptr;
	__uint128_t *pre_yz_b = nullptr;
	uint64_t *vole_triples_a = nullptr;
	__uint128_t *vole_triples_b = nullptr;

	BaseCot<IO> *cot;
	OTPre<IO> *pre_ot = nullptr;

	uint64_t Delta;
	LpnFp<LPN_D> * lpn = nullptr;
	ThreadPool * pool = nullptr;
	MpfssRegFp<IO> * mpfss = nullptr;

	VoleTriple (int party, int threads, IO **ios) {
        	this->io = ios[0];
		this->threads = threads;
		this->party = party;
		this->ios = ios;
		set_param();
		this->extend_initialized = false;

		cot = new BaseCot<IO>(party, io, true);
		cot->cot_gen_pre();

		pool = new ThreadPool(threads);
	}

	~VoleTriple() {
		if(pre_yz_a != nullptr) delete[] pre_yz_a;
		if(pre_yz_b != nullptr) delete[] pre_yz_b;
		if(pre_ot != nullptr) delete pre_ot;
		if(lpn != nullptr) delete lpn;
		if(pool != nullptr) delete pool;
		if(mpfss != nullptr) delete mpfss;
		if(vole_triples_a != nullptr) delete[] vole_triples_a;
		if(vole_triples_b != nullptr) delete[] vole_triples_b;
	}

	void set_param() {
		this->n = N_REG_Fp;
		this->k = K_REG_Fp;
		this->t = T_REG_Fp;
		this->log_bin_sz = BIN_SZ_REG_Fp;
	}

	void setup(uint64_t delta) {
		this->Delta = delta;
		setup();
	}

	uint64_t delta() {
		if(party == ALICE)
			return this->Delta;
		else {
			error("No delta for BOB");
			return 0;
		}
	}

	void extend_initialization() {
		lpn = new LpnFp<LPN_D>(n, k, pool, pool->size());
		mpfss = new MpfssRegFp<IO>(party, threads, n, t, log_bin_sz, pool, ios); 
		mpfss->set_malicious();

		pre_ot = new OTPre<IO>(io, mpfss->tree_height-1, mpfss->tree_n);
		M = k + t + 1;
		ot_limit = n - M;
		ot_used = ot_limit;
		extend_initialized = true;
	}

	// sender extend
	void extend_send(uint64_t *y, 
			MpfssRegFp<IO> *mpfss, 
			OTPre<IO> *pre_ot, 
			LpnFp<LPN_D> *lpn,
			uint64_t *key) {
		mpfss->sender_init(Delta);
		mpfss->mpfss(y, key, pre_ot);
		lpn->compute_send(y, key+mpfss->tree_n+1);
	}

	// receiver extend
	void extend_recv(__uint128_t *z,
			MpfssRegFp<IO> *mpfss,
			OTPre<IO> *pre_ot, 
			LpnFp<LPN_D> *lpn,
			__uint128_t *mac) {
		mpfss->recver_init();
		mpfss->mpfss(z, mac, pre_ot);
		lpn->compute_recv(z, mac+mpfss->tree_n+1);
	}

	void extend(uint64_t *buffer) {
		cot->cot_gen(pre_ot, pre_ot->n);
        extend_send(buffer, mpfss, pre_ot, lpn, pre_yz_a);
        memcpy(pre_yz_a, buffer+ot_limit, M*sizeof(uint64_t));
	}

	void extend(__uint128_t *buffer) {
		cot->cot_gen(pre_ot, pre_ot->n);
        extend_recv(buffer, mpfss, pre_ot, lpn, pre_yz_b);
        memcpy(pre_yz_b, buffer+ot_limit, M*sizeof(__uint128_t));
	}

	void setup() {
		// initialize the main process
		ThreadPool pool_tmp(1);
		auto fut = pool_tmp.enqueue([this](){
			extend_initialization();
		});

		// pre-processing tools
		LpnFp<LPN_D> lpn_pre0(N_PRE0_REG_Fp, K_PRE0_REG_Fp, pool, pool->size());
		MpfssRegFp<IO> mpfss_pre0(party, threads, N_PRE0_REG_Fp, T_PRE0_REG_Fp, BIN_SZ_PRE0_REG_Fp, pool, ios);
		mpfss_pre0.set_malicious();
		OTPre<IO> pre_ot_ini0(ios[0], mpfss_pre0.tree_height-1, mpfss_pre0.tree_n);

		// generate tree_n*(depth-1) COTs
		int M_pre0 = pre_ot_ini0.n;
		cot->cot_gen(&pre_ot_ini0, M_pre0);

		Base_svole<IO> *svole0;
		int triple_n0 = 1+mpfss_pre0.tree_n+K_PRE0_REG_Fp;

		// pre-processing tools
		LpnFp<LPN_D> lpn_pre(N_PRE_REG_Fp, K_PRE_REG_Fp, pool, pool->size());
		MpfssRegFp<IO> mpfss_pre(party, threads, N_PRE_REG_Fp, T_PRE_REG_Fp, BIN_SZ_PRE_REG_Fp, pool, ios);
		mpfss_pre.set_malicious();
		OTPre<IO> pre_ot_ini(ios[0], mpfss_pre.tree_height-1, mpfss_pre.tree_n);

		// generate tree_n*(depth-1) COTs
		int M_pre = pre_ot_ini.n;
		cot->cot_gen(&pre_ot_ini, M_pre);

        if(party == ALICE) {
		    // space for pre-processing triples
            uint64_t *pre_yz0 = new uint64_t[N_PRE0_REG_Fp];
            memset(pre_yz0, 0, N_PRE0_REG_Fp*sizeof(uint64_t));

		    // generate 2*tree_n+k_pre triples and extend
			uint64_t *key = new uint64_t[triple_n0];
			svole0 = new Base_svole<IO>(party, ios[0], Delta);
			svole0->triple_gen_send(key, triple_n0);

			extend_send(pre_yz0, &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, key);
			delete[] key;

	    	delete svole0;

            // space for pre-processing triples
            pre_yz_a = new uint64_t[N_PRE_REG_Fp];
            memset(pre_yz_a, 0, N_PRE_REG_Fp*sizeof(uint64_t));

		    // generate 2*tree_n+k_pre triples and extend
			extend_send(pre_yz_a, &mpfss_pre, &pre_ot_ini, &lpn_pre, pre_yz0);
		    delete[] pre_yz0;

            if(vole_triples_a == nullptr)
                vole_triples_a = new uint64_t[n];
        } else {
		    // space for pre-processing triples
            __uint128_t *pre_yz0 = new __uint128_t[N_PRE0_REG_Fp];
            memset(pre_yz0, 0, N_PRE0_REG_Fp*sizeof(__uint128_t));

		    // generate 2*tree_n+k_pre triples and extend
			__uint128_t *mac = new __uint128_t[triple_n0];
			svole0 = new Base_svole<IO>(party, ios[0]);
			svole0->triple_gen_recv(mac, triple_n0);

			extend_recv(pre_yz0, &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, mac);
			delete[] mac;

		    delete svole0;

            // space for pre-processing triples
            pre_yz_b = new __uint128_t[N_PRE_REG_Fp];
            memset(pre_yz_b, 0, N_PRE_REG_Fp*sizeof(__uint128_t));

		    // generate 2*tree_n+k_pre triples and extend
			extend_recv(pre_yz_b, &mpfss_pre, &pre_ot_ini, &lpn_pre, pre_yz0);
		    delete[] pre_yz0;

            if(vole_triples_b == nullptr)
                vole_triples_b = new __uint128_t[n];
        }

		pre_ot_inplace = true;


		fut.get();
	}

    template<typename T>
    void memcpy_online(T *dest, int src_offset, int num) {
        if(party == ALICE)
            memcpy(dest, vole_triples_a+src_offset, num*sizeof(uint64_t));
        else memcpy(dest, vole_triples_b+src_offset, num*sizeof(__uint128_t));
    }

    void extend_online() {
        if(party == ALICE) extend(vole_triples_a);
        else extend(vole_triples_b);
    }

    template<typename T>
	void extend(T *data_yz, int num) {
		if(extend_initialized == false) 
			error("Run setup before extending");
		if(num <= silent_ot_left()) {
			//memcpy(data_yz, vole_triples+ot_used, num*sizeof(__uint128_t));
            memcpy_online(data_yz, ot_used, num);
			this->ot_used += num;
			return;
		}
		T *pt = data_yz;
		int gened = silent_ot_left();
		if(gened > 0) {
			//memcpy(pt, vole_triples+ot_used, gened*sizeof(__uint128_t));
            memcpy_online(pt, ot_used, gened);
			pt += gened;
		}
		int round_inplace = (num-gened-M) / ot_limit;
		int last_round_ot = num-gened-round_inplace*ot_limit;
		bool round_memcpy = last_round_ot>ot_limit?true:false;
		if(round_memcpy) last_round_ot -= ot_limit;
		for(int i = 0; i < round_inplace; ++i) {
			extend(pt);
			ot_used = ot_limit;
			pt += ot_limit;
		}
		if(round_memcpy) {
			//extend(vole_triples);
            extend_online();
			//memcpy(pt, vole_triples, ot_limit*sizeof(__uint128_t)); 
            memcpy_online(pt, 0, ot_limit);
			ot_used = ot_limit;
			pt += ot_limit;
		}
		if(last_round_ot > 0) {
			//extend(vole_triples);
            extend_online();
			//memcpy(pt, vole_triples, last_round_ot*sizeof(__uint128_t));
            memcpy_online(pt, 0, last_round_ot);
			ot_used = last_round_ot;
		}
	}

    template<typename T>
	uint64_t extend_inplace(T *data_yz, int byte_space) {
		if(byte_space < n) error("space not enough");
		uint64_t tp_output_n = byte_space - M;
		if(tp_output_n % ot_limit != 0) error("call byte_memory_need_inplace \
				to get the correct length of memory space");
		int round = tp_output_n / ot_limit;
		T *pt = data_yz;
		for(int i = 0; i < round; ++i) {
			extend(pt);
			pt += ot_limit;
		}
		return tp_output_n;
	}

	uint64_t byte_memory_need_inplace(uint64_t tp_need) {
		int round = (tp_need - 1) / ot_limit;
		return round * ot_limit + n;
	}

	int silent_ot_left() {
		return ot_limit - ot_used;
	}

	// debug function
	void check_triple(uint64_t x, uint64_t* y, int size) {
        io->send_data(&x, sizeof(uint64_t));
        io->send_data(y, size*sizeof(uint64_t));
	}

	void check_triple(__uint128_t* y, int size) {
        uint64_t delta;
        uint64_t *k = new uint64_t[size];
        io->recv_data(&delta, sizeof(uint64_t));
        io->recv_data(k, size*sizeof(uint64_t));
        for(int i = 0; i < size; ++i) {
            uint64_t tmp = mult_mod(delta, _mm_extract_epi64((block)y[i],1));
            tmp = add_mod(tmp, k[i]);
            if(tmp != _mm_extract_epi64((block)y[i], 0)) {
                std::cout << "triple error at index: " << i << std::endl;
                abort();
            }
		}
	}
};
#endif// _ITERATIVE_COT_H_
