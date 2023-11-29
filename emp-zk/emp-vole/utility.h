#ifndef FP_UTILITY_H__
#define FP_UTILITY_H__
#include "emp-tool/emp-tool.h"
using namespace emp;
using namespace std;

/* mult */
#if  defined(__x86_64__) && defined(__BMI2__)
inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t * c) {
	return _mulx_u64((unsigned long long )a, (unsigned long long) b, (unsigned long long*)c);
}
//
#else
inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t * c) {
	__uint128_t aa = a;
	__uint128_t bb = b;
	auto cc = aa*bb;
	*c = cc>>64;
	return (uint64_t)cc;
}
#endif

// 2^59 - 2^28 + 1
#define MERSENNE_PRIME_EXP 59
const static __uint128_t p = 576460752034988033;
const static __uint128_t pr = 576460752034988033;
const static block prs = makeBlock(576460752034988033,
        576460752034988033);
const static uint64_t PR = 576460752034988033;
static __m128i PRs = makeBlock(PR, PR);

const static uint64_t low_59b_mask = (1ULL << 59) - 1;
const static block low_59b_masks = makeBlock((1ULL<<59)-1,(1ULL<<59)-1);

inline uint64_t mod(uint64_t x) {
    uint64_t i = x >> 59;
	i = (i << 28) - i + (x & low_59b_mask);
	return (i >= PR) ? i - PR : i;
}

template<typename T>
T mod(T k, T pv) {
    T i = k >> 59;
	i = (i << 28) - i + (k & low_59b_mask);
	return (i >= pv) ? i - pv : i;
}

inline block vec_partial_mod(block i) {
	return _mm_sub_epi64(i, _mm_andnot_si128(_mm_cmpgt_epi64(prs,i), prs));
}

inline block vec_mod(block i) {
    block x = _mm_srli_epi64(i, 59);
    x = _mm_sub_epi64(_mm_slli_epi64(x, 28), x);
	x = _mm_add_epi64(x, i & low_59b_masks);
	return vec_partial_mod(x);
}

inline uint64_t mult_mod(uint64_t a, uint64_t b) {
	uint64_t c = 0;
	uint64_t e = mul64(a, b, (uint64_t*)&c);
    uint64_t i = (c<<5) + (e>>59);

    uint64_t j = i >> 31;
    j = (j << 28) - j + ((i << 28) & low_59b_mask);
    j = (j >= PR) ? j-PR : j;

    i = j + (e & low_59b_mask) + PR - i;
    i = (i >= PR) ? (i - PR) : i;
    return (i >= PR) ? (i - PR) : i;
}

inline block mult_mod(block a, uint64_t b) {
	uint64_t H = _mm_extract_epi64(a, 1);
	uint64_t L = _mm_extract_epi64(a, 0);
	block bs[2];
	uint64_t * is = (uint64_t*)(bs);
	is[1] = mul64(H, b, (uint64_t*)(is+3));
	is[0] = mul64(L, b, (uint64_t*)(is+2));
    block t1 = _mm_add_epi64(_mm_slli_epi64(bs[1], 5), _mm_srli_epi64(bs[0], 59));

    block t2 = _mm_srli_epi64(t1, 31);
    block t3 = _mm_slli_epi64(t2, 28);
    t3 = _mm_sub_epi64(t3, t2);
    t3 = _mm_add_epi64(t3, _mm_slli_epi64(t1, 28) & low_59b_masks);
    t3 = _mm_sub_epi64(t3, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t3), prs));

    t3 = _mm_add_epi64(t3, bs[0]&low_59b_masks);
    t1 = _mm_sub_epi64(prs, t1);
    t3 = _mm_add_epi64(t3, t1); 
	t3 = _mm_sub_epi64(t3, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t3), prs));
    return _mm_sub_epi64(t3, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t3), prs));
}

/*inline block mult_mod(block a, block b) {
	uint64_t H = _mm_extract_epi64(a, 1);
	uint64_t L = _mm_extract_epi64(a, 0);
    uint64_t Hb = _mm_extract_epi64(b, 1);
	uint64_t Lb = _mm_extract_epi64(b, 0);
	block bs[2];
	uint64_t * is = (uint64_t*)(bs);
	is[1] = mul64(H, Hb, (uint64_t*)(is+3));
	is[0] = mul64(L, Lb, (uint64_t*)(is+2));
    block t1 = _mm_add_epi64(_mm_slli_epi64(bs[1], 5), _mm_srli_epi64(bs[0], 59));
    block t2 = t1;
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 3);
    t2 = vec_mod(t2);
    t2 = _mm_add_epi64(t2, bs[0]&low_59b_masks);
    t1 = _mm_sub_epi64(prs, t1);
    t2 = _mm_add_epi64(t2, t1); 
	t2 = _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
    return _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
}*/

//#if _FIELD_2p59m2p11m1_ == 1

/*#define MERSENNE_PRIME_EXP 59
const static __uint128_t p = 576460752303421441;
const static __uint128_t pr = 576460752303421441;
const static block prs = makeBlock(576460752303421441ULL,
        576460752303421441ULL);
const static uint64_t PR = 576460752303421441;
static __m128i PRs = makeBlock(PR, PR);

const static uint64_t low_59b_mask = (1ULL << 59) - 1;
const static block low_59b_masks = makeBlock((1ULL<<59)-1,(1ULL<<59)-1);

inline uint64_t mod(uint64_t x) {
    uint64_t i = x >> 59;
	i = (i << 11) - i + (x & low_59b_mask);
	return (i >= PR) ? i - PR : i;
}

template<typename T>
T mod(T k, T pv) {
    T i = k >> 59;
	i = (i << 11) - i + (k & low_59b_mask);
	return (i >= pv) ? i - pv : i;
}

inline block vec_partial_mod(block i) {
	return _mm_sub_epi64(i, _mm_andnot_si128(_mm_cmpgt_epi64(prs,i), prs));
}

inline block vec_mod(block i) {
    block x = _mm_srli_epi64(i, 59);
    x = _mm_sub_epi64(_mm_slli_epi64(x, 11), x);
	x = _mm_add_epi64(x, i & low_59b_masks);
	return vec_partial_mod(x);
}

inline uint64_t mult_mod(uint64_t a, uint64_t b) {
	uint64_t c = 0;
	uint64_t e = mul64(a, b, (uint64_t*)&c);
    uint64_t i = (c<<5) + (e>>59); 

    uint64_t j = i;
    j <<= 4; j = mod(j);
    j <<= 4; j = mod(j);
    j <<= 3; j = mod(j);
    i = j + (e & low_59b_mask) + PR - i;
    i = (i >= PR) ? (i - PR) : i;
    return (i >= PR) ? (i - PR) : i;
}

inline block mult_mod(block a, uint64_t b) {
	uint64_t H = _mm_extract_epi64(a, 1);
	uint64_t L = _mm_extract_epi64(a, 0);
	block bs[2];
	uint64_t * is = (uint64_t*)(bs);
	is[1] = mul64(H, b, (uint64_t*)(is+3));
	is[0] = mul64(L, b, (uint64_t*)(is+2));
    block t1 = _mm_add_epi64(_mm_slli_epi64(bs[1], 5), _mm_srli_epi64(bs[0], 59));
    block t2 = t1;
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 3);
    t2 = vec_mod(t2);
    t2 = _mm_add_epi64(t2, bs[0]&low_59b_masks);
    t1 = _mm_sub_epi64(prs, t1);
    t2 = _mm_add_epi64(t2, t1); 
	t2 = _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
    return _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
}

inline block mult_mod(block a, block b) {
	uint64_t H = _mm_extract_epi64(a, 1);
	uint64_t L = _mm_extract_epi64(a, 0);
    uint64_t Hb = _mm_extract_epi64(b, 1);
	uint64_t Lb = _mm_extract_epi64(b, 0);
	block bs[2];
	uint64_t * is = (uint64_t*)(bs);
	is[1] = mul64(H, Hb, (uint64_t*)(is+3));
	is[0] = mul64(L, Lb, (uint64_t*)(is+2));
    block t1 = _mm_add_epi64(_mm_slli_epi64(bs[1], 5), _mm_srli_epi64(bs[0], 59));
    block t2 = t1;
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 4);
    t2 = vec_mod(t2);
    t2 = _mm_slli_epi64(t2, 3);
    t2 = vec_mod(t2);
    t2 = _mm_add_epi64(t2, bs[0]&low_59b_masks);
    t1 = _mm_sub_epi64(prs, t1);
    t2 = _mm_add_epi64(t2, t1); 
	t2 = _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
    return _mm_sub_epi64(t2, _mm_andnot_si128(_mm_cmpgt_epi64(prs,t2), prs));
}*/
/*
#elif _FIELD_2p61m1_ == 1

#define MERSENNE_PRIME_EXP 61
const static __uint128_t p = 2305843009213693951;
const static __uint128_t pr = 2305843009213693951;
const static block prs = makeBlock(2305843009213693951ULL, 2305843009213693951ULL);
const static uint64_t PR = 2305843009213693951;
static __m128i PRs = makeBlock(PR, PR);

// mod
inline uint64_t mod(uint64_t x) {
	uint64_t i = (x & PR) + (x >> MERSENNE_PRIME_EXP);
	return (i >= p) ? i - p : i;
}

template<typename T>
T mod(T k, T pv) {
	T i = (k & pv) + (k >> MERSENNE_PRIME_EXP);
	return (i >= pv) ? i - pv : i;
}

inline block vec_partial_mod(block i) {
	return _mm_sub_epi64(i, _mm_andnot_si128(_mm_cmpgt_epi64(prs,i), prs));
}

inline block vec_mod(block i) {
	i = _mm_add_epi64((i & prs), _mm_srli_epi64(i, MERSENNE_PRIME_EXP));
	return vec_partial_mod(i);
}

inline uint64_t mult_mod(uint64_t a, uint64_t b) {
	uint64_t c = 0;
	uint64_t e = mul64(a, b, (uint64_t*)&c);
	uint64_t res =  (e & PR) + ( (e>>MERSENNE_PRIME_EXP) ^ (c<< (64-MERSENNE_PRIME_EXP)));
	return (res >= PR) ? (res - PR) : res;
}

inline block mult_mod(block a, uint64_t b) {
	uint64_t H = _mm_extract_epi64(a, 1);
	uint64_t L = _mm_extract_epi64(a, 0);
	block bs[2];
	uint64_t * is = (uint64_t*)(bs);
//	uint64_t h0, h1, l0, l1;
	is[1] = mul64(H, b, (uint64_t*)(is+3));
	is[0] = mul64(L, b, (uint64_t*)(is+2));
	//block Hb = _mm_set_epi64((__m64)h1, (__m64)l1); 
	//block Lb = _mm_set_epi64((__m64)h0, (__m64)l0);
	block t1 = bs[0] & prs;
	block t2 = _mm_srli_epi64(bs[0], MERSENNE_PRIME_EXP) ^ _mm_slli_epi64(bs[1], 64 - MERSENNE_PRIME_EXP);
	block res = _mm_add_epi64(t1, t2);
	return vec_partial_mod(res);
}
#endif*/

/* add */
inline block add_mod(block a, block b) {
	block res = _mm_add_epi64(a, b);
	return vec_partial_mod(res);
}

inline block add_mod(block a, uint64_t b) {
	block res = _mm_add_epi64(a, _mm_set_epi64((__m64)b, (__m64)b));
	return vec_partial_mod(res);
}

inline uint64_t add_mod(uint64_t a, uint64_t b) {
	uint64_t res = a + b;
	return (res >= PR) ? (res - PR) : res;
}

inline void extract_fp(__uint128_t& x) {
	x = mod(_mm_extract_epi64((block)x, 0));
}

/* generate coefficient from seed */
template<typename T>
void uni_hash_coeff_gen(T* coeff, T seed, int sz) {
	coeff[0] = seed;
	for(int i = 1; i < sz; ++i)
		coeff[i] = mult_mod(coeff[i-1], seed);
}

/* inner product */
template<typename T>
T vector_inn_prdt_sum_red(const T *a, const T *b, int sz) {
	T res = (T)0;
	for(int i = 0; i < sz; ++i)
		res = add_mod(res, mult_mod(a[i], b[i]));
	return res;
}

template<typename S, typename T>
T vector_inn_prdt_sum_red(const S *a, const T *b, int sz) {
	T res = (T)0;
	for(int i = 0; i < sz; ++i)
		res = add_mod(res, mult_mod((T)a[i], b[i]));
	return res;
}

#endif
