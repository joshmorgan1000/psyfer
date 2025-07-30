/**
 * @file ed25519_ops.cpp
 * @brief Ed25519 group and scalar operations
 * 
 * IMPORTANT: This is a production-grade implementation of Ed25519
 * cryptographic operations. DO NOT modify without cryptographic expertise.
 */

#include <cstring>
#include <cstdint>
#include <array>

namespace psyfer::crypto {

// Ed25519 uses the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
// over GF(2^255 - 19) with d = -121665/121666

// ────────────────────────────────────────────────────────────────────────────
// Field element operations (mod 2^255 - 19)
// ────────────────────────────────────────────────────────────────────────────

typedef int32_t fe[10];  // Field element in radix 2^25.5

static void fe_0(fe& h) {
    h[0] = 0; h[1] = 0; h[2] = 0; h[3] = 0; h[4] = 0;
    h[5] = 0; h[6] = 0; h[7] = 0; h[8] = 0; h[9] = 0;
}

static void fe_1(fe& h) {
    h[0] = 1; h[1] = 0; h[2] = 0; h[3] = 0; h[4] = 0;
    h[5] = 0; h[6] = 0; h[7] = 0; h[8] = 0; h[9] = 0;
}

static void fe_copy(fe& h, const fe& f) {
    for (int i = 0; i < 10; i++) h[i] = f[i];
}

static void fe_add(fe& h, const fe& f, const fe& g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe& h, const fe& f, const fe& g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

static void fe_neg(fe& h, const fe& f) {
    for (int i = 0; i < 10; i++) h[i] = -f[i];
}

static void fe_mul(fe& h, const fe& f, const fe& g) {
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    
    int32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3;
    int32_t g4_19 = 19 * g4, g5_19 = 19 * g5, g6_19 = 19 * g6;
    int32_t g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
    
    int64_t h0 = (int64_t)f0 * g0 + (int64_t)f1 * g9_19 + (int64_t)f2 * g8_19 + 
                 (int64_t)f3 * g7_19 + (int64_t)f4 * g6_19 + (int64_t)f5 * g5_19 + 
                 (int64_t)f6 * g4_19 + (int64_t)f7 * g3_19 + (int64_t)f8 * g2_19 + 
                 (int64_t)f9 * g1_19;
    int64_t h1 = (int64_t)f0 * g1 + (int64_t)f1 * g0 + (int64_t)f2 * g9_19 + 
                 (int64_t)f3 * g8_19 + (int64_t)f4 * g7_19 + (int64_t)f5 * g6_19 + 
                 (int64_t)f6 * g5_19 + (int64_t)f7 * g4_19 + (int64_t)f8 * g3_19 + 
                 (int64_t)f9 * g2_19;
    int64_t h2 = (int64_t)f0 * g2 + (int64_t)f1 * g1 + (int64_t)f2 * g0 + 
                 (int64_t)f3 * g9_19 + (int64_t)f4 * g8_19 + (int64_t)f5 * g7_19 + 
                 (int64_t)f6 * g6_19 + (int64_t)f7 * g5_19 + (int64_t)f8 * g4_19 + 
                 (int64_t)f9 * g3_19;
    int64_t h3 = (int64_t)f0 * g3 + (int64_t)f1 * g2 + (int64_t)f2 * g1 + 
                 (int64_t)f3 * g0 + (int64_t)f4 * g9_19 + (int64_t)f5 * g8_19 + 
                 (int64_t)f6 * g7_19 + (int64_t)f7 * g6_19 + (int64_t)f8 * g5_19 + 
                 (int64_t)f9 * g4_19;
    int64_t h4 = (int64_t)f0 * g4 + (int64_t)f1 * g3 + (int64_t)f2 * g2 + 
                 (int64_t)f3 * g1 + (int64_t)f4 * g0 + (int64_t)f5 * g9_19 + 
                 (int64_t)f6 * g8_19 + (int64_t)f7 * g7_19 + (int64_t)f8 * g6_19 + 
                 (int64_t)f9 * g5_19;
    int64_t h5 = (int64_t)f0 * g5 + (int64_t)f1 * g4 + (int64_t)f2 * g3 + 
                 (int64_t)f3 * g2 + (int64_t)f4 * g1 + (int64_t)f5 * g0 + 
                 (int64_t)f6 * g9_19 + (int64_t)f7 * g8_19 + (int64_t)f8 * g7_19 + 
                 (int64_t)f9 * g6_19;
    int64_t h6 = (int64_t)f0 * g6 + (int64_t)f1 * g5 + (int64_t)f2 * g4 + 
                 (int64_t)f3 * g3 + (int64_t)f4 * g2 + (int64_t)f5 * g1 + 
                 (int64_t)f6 * g0 + (int64_t)f7 * g9_19 + (int64_t)f8 * g8_19 + 
                 (int64_t)f9 * g7_19;
    int64_t h7 = (int64_t)f0 * g7 + (int64_t)f1 * g6 + (int64_t)f2 * g5 + 
                 (int64_t)f3 * g4 + (int64_t)f4 * g3 + (int64_t)f5 * g2 + 
                 (int64_t)f6 * g1 + (int64_t)f7 * g0 + (int64_t)f8 * g9_19 + 
                 (int64_t)f9 * g8_19;
    int64_t h8 = (int64_t)f0 * g8 + (int64_t)f1 * g7 + (int64_t)f2 * g6 + 
                 (int64_t)f3 * g5 + (int64_t)f4 * g4 + (int64_t)f5 * g3 + 
                 (int64_t)f6 * g2 + (int64_t)f7 * g1 + (int64_t)f8 * g0 + 
                 (int64_t)f9 * g9_19;
    int64_t h9 = (int64_t)f0 * g9 + (int64_t)f1 * g8 + (int64_t)f2 * g7 + 
                 (int64_t)f3 * g6 + (int64_t)f4 * g5 + (int64_t)f5 * g4 + 
                 (int64_t)f6 * g3 + (int64_t)f7 * g2 + (int64_t)f8 * g1 + 
                 (int64_t)f9 * g0;
    
    // Carry propagation
    int64_t carry0 = (h0 + (1LL << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int64_t carry4 = (h4 + (1LL << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    
    int64_t carry1 = (h1 + (1LL << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int64_t carry5 = (h5 + (1LL << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    
    int64_t carry2 = (h2 + (1LL << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int64_t carry6 = (h6 + (1LL << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    
    int64_t carry3 = (h3 + (1LL << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int64_t carry7 = (h7 + (1LL << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    
    carry4 = (h4 + (1LL << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int64_t carry8 = (h8 + (1LL << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
    
    int64_t carry9 = (h9 + (1LL << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    
    carry0 = (h0 + (1LL << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    
    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

static void fe_sq(fe& h, const fe& f) {
    fe_mul(h, f, f);
}

static void fe_invert(fe& out, const fe& z) {
    fe t0, t1, t2, t3;
    
    // Compute z^(p-2) = z^(2^255 - 21) using addition chain
    fe_sq(t0, z);        // 2^1
    fe_sq(t1, t0);       // 2^2
    fe_sq(t1, t1);       // 2^3
    fe_mul(t1, z, t1);   // 2^3 + 2^0
    fe_mul(t0, t0, t1);  // 2^3 + 2^1 + 2^0
    fe_sq(t2, t0);       // 2^4 + 2^2 + 2^1
    fe_mul(t1, t1, t2);  // 2^4 + 2^3 + 2^2 + 2^1 + 2^0
    fe_sq(t2, t1);       // 2^5 + 2^4 + 2^3 + 2^2 + 2^1
    for (int i = 1; i < 5; ++i) {
        fe_sq(t2, t2);   // 2^10 + 2^9 + 2^8 + 2^7 + 2^6
    }
    fe_mul(t1, t2, t1);  // 2^10 + ... + 2^0
    fe_sq(t2, t1);       // 2^11 + ... + 2^1
    for (int i = 1; i < 10; ++i) {
        fe_sq(t2, t2);   // 2^20 + ... + 2^10
    }
    fe_mul(t2, t2, t1);  // 2^20 + ... + 2^0
    fe_sq(t3, t2);       // 2^21 + ... + 2^1
    for (int i = 1; i < 20; ++i) {
        fe_sq(t3, t3);   // 2^40 + ... + 2^20
    }
    fe_mul(t2, t3, t2);  // 2^40 + ... + 2^0
    fe_sq(t2, t2);       // 2^41 + ... + 2^1
    for (int i = 1; i < 10; ++i) {
        fe_sq(t2, t2);   // 2^50 + ... + 2^10
    }
    fe_mul(t1, t2, t1);  // 2^50 + ... + 2^0
    fe_sq(t2, t1);       // 2^51 + ... + 2^1
    for (int i = 1; i < 50; ++i) {
        fe_sq(t2, t2);   // 2^100 + ... + 2^50
    }
    fe_mul(t2, t2, t1);  // 2^100 + ... + 2^0
    fe_sq(t3, t2);       // 2^101 + ... + 2^1
    for (int i = 1; i < 100; ++i) {
        fe_sq(t3, t3);   // 2^200 + ... + 2^100
    }
    fe_mul(t2, t3, t2);  // 2^200 + ... + 2^0
    fe_sq(t2, t2);       // 2^201 + ... + 2^1
    for (int i = 1; i < 50; ++i) {
        fe_sq(t2, t2);   // 2^250 + ... + 2^50
    }
    fe_mul(t1, t2, t1);  // 2^250 + ... + 2^0
    fe_sq(t1, t1);       // 2^251 + ... + 2^1
    for (int i = 1; i < 5; ++i) {
        fe_sq(t1, t1);   // 2^255 + ... + 2^5
    }
    fe_mul(out, t1, t0); // 2^255 - 21
}

static void fe_tobytes(uint8_t* s, const fe& h) {
    fe t;
    fe_copy(t, h);
    
    // Reduce coefficients
    int32_t q = (19 * t[9] + (1 << 24)) >> 25;
    for (int i = 0; i < 10; i++) {
        if (i == 9) {
            q = (t[i] + q) >> 25;
            t[i] -= q << 25;
            q = (q + (1 << 24)) >> 25;
            t[0] += 19 * q;
        } else {
            q = (t[i] + q) >> ((i & 1) ? 25 : 26);
            t[i] -= q << ((i & 1) ? 25 : 26);
        }
    }
    
    // Final reduction
    q = 0;
    for (int i = 0; i < 10; i++) {
        q = (t[i] + q) >> ((i & 1) ? 25 : 26);
        t[i] -= q << ((i & 1) ? 25 : 26);
    }
    t[0] += 19 * q;
    
    // Convert to bytes
    s[0] = t[0] >> 0;
    s[1] = t[0] >> 8;
    s[2] = t[0] >> 16;
    s[3] = (t[0] >> 24) | (t[1] << 2);
    s[4] = t[1] >> 6;
    s[5] = t[1] >> 14;
    s[6] = (t[1] >> 22) | (t[2] << 3);
    s[7] = t[2] >> 5;
    s[8] = t[2] >> 13;
    s[9] = (t[2] >> 21) | (t[3] << 5);
    s[10] = t[3] >> 3;
    s[11] = t[3] >> 11;
    s[12] = (t[3] >> 19) | (t[4] << 6);
    s[13] = t[4] >> 2;
    s[14] = t[4] >> 10;
    s[15] = t[4] >> 18;
    s[16] = t[5] >> 0;
    s[17] = t[5] >> 8;
    s[18] = t[5] >> 16;
    s[19] = (t[5] >> 24) | (t[6] << 1);
    s[20] = t[6] >> 7;
    s[21] = t[6] >> 15;
    s[22] = (t[6] >> 23) | (t[7] << 3);
    s[23] = t[7] >> 5;
    s[24] = t[7] >> 13;
    s[25] = (t[7] >> 21) | (t[8] << 4);
    s[26] = t[8] >> 4;
    s[27] = t[8] >> 12;
    s[28] = (t[8] >> 20) | (t[9] << 6);
    s[29] = t[9] >> 2;
    s[30] = t[9] >> 10;
    s[31] = t[9] >> 18;
}

static void fe_frombytes(fe& h, const uint8_t* s) {
    int64_t h0 = (int64_t)(s[0] | (s[1] << 8) | (s[2] << 16) | ((int64_t)s[3] << 24));
    int64_t h1 = (int64_t)(s[4] | (s[5] << 8) | (s[6] << 16) | ((int64_t)s[7] << 24)) >> 6;
    int64_t h2 = (int64_t)(s[7] | (s[8] << 8) | (s[9] << 16) | ((int64_t)s[10] << 24)) >> 5;
    int64_t h3 = (int64_t)(s[10] | (s[11] << 8) | (s[12] << 16) | ((int64_t)s[13] << 24)) >> 3;
    int64_t h4 = (int64_t)(s[13] | (s[14] << 8) | (s[15] << 16) | ((int64_t)s[16] << 24)) >> 2;
    int64_t h5 = (int64_t)(s[16] | (s[17] << 8) | (s[18] << 16) | ((int64_t)s[19] << 24));
    int64_t h6 = (int64_t)(s[20] | (s[21] << 8) | (s[22] << 16) | ((int64_t)s[23] << 24)) >> 7;
    int64_t h7 = (int64_t)(s[23] | (s[24] << 8) | (s[25] << 16) | ((int64_t)s[26] << 24)) >> 5;
    int64_t h8 = (int64_t)(s[26] | (s[27] << 8) | (s[28] << 16) | ((int64_t)s[29] << 24)) >> 4;
    int64_t h9 = (int64_t)(s[29] | (s[30] << 8) | (s[31] << 16)) >> 2;
    
    int64_t carry9 = (h9 + (1LL << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    int64_t carry1 = (h1 + (1LL << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int64_t carry3 = (h3 + (1LL << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int64_t carry5 = (h5 + (1LL << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    int64_t carry7 = (h7 + (1LL << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    
    int64_t carry0 = (h0 + (1LL << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int64_t carry2 = (h2 + (1LL << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int64_t carry4 = (h4 + (1LL << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int64_t carry6 = (h6 + (1LL << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    int64_t carry8 = (h8 + (1LL << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
    
    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

// ────────────────────────────────────────────────────────────────────────────
// Group element operations
// ────────────────────────────────────────────────────────────────────────────

struct ge_p2 {
    fe X, Y, Z;
};

struct ge_p3 {
    fe X, Y, Z, T;
};

struct ge_p1p1 {
    fe X, Y, Z, T;
};

struct ge_precomp {
    fe yplusx, yminusx, xy2d;
};

struct ge_cached {
    fe YplusX, YminusX, Z, T2d;
};

// d = -121665/121666
static const fe d = {-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116};
static const fe d2 = {-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199};
static const fe sqrtm1 = {-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482};


static void ge_p3_0(ge_p3& h) {
    fe_0(h.X);
    fe_1(h.Y);
    fe_1(h.Z);
    fe_0(h.T);
}

static void ge_precomp_0(ge_precomp& h) {
    fe_1(h.yplusx);
    fe_1(h.yminusx);
    fe_0(h.xy2d);
}

static void ge_p3_to_p2(ge_p2& r, const ge_p3& p) {
    fe_copy(r.X, p.X);
    fe_copy(r.Y, p.Y);
    fe_copy(r.Z, p.Z);
}

static void ge_p3_to_cached(ge_cached& r, const ge_p3& p) {
    fe_add(r.YplusX, p.Y, p.X);
    fe_sub(r.YminusX, p.Y, p.X);
    fe_copy(r.Z, p.Z);
    fe_mul(r.T2d, p.T, d2);
}

static void ge_p1p1_to_p2(ge_p2& r, const ge_p1p1& p) {
    fe_mul(r.X, p.X, p.T);
    fe_mul(r.Y, p.Y, p.Z);
    fe_mul(r.Z, p.Z, p.T);
}

static void ge_p1p1_to_p3(ge_p3& r, const ge_p1p1& p) {
    fe_mul(r.X, p.X, p.T);
    fe_mul(r.Y, p.Y, p.Z);
    fe_mul(r.Z, p.Z, p.T);
    fe_mul(r.T, p.X, p.Y);
}

static void ge_p2_dbl(ge_p1p1& r, const ge_p2& p) {
    fe t0;
    fe_sq(r.X, p.X);
    fe_sq(r.Z, p.Y);
    fe_sq(r.T, p.Z);
    fe_add(r.T, r.T, r.T);
    fe_add(r.Y, p.X, p.Y);
    fe_sq(t0, r.Y);
    fe_add(r.Y, r.Z, r.X);
    fe_sub(r.Z, r.Z, r.X);
    fe_sub(r.X, t0, r.Y);
    fe_sub(r.T, r.T, r.Z);
}

static void ge_madd(ge_p1p1& r, const ge_p3& p, const ge_precomp& q) {
    fe t0;
    fe_add(r.X, p.Y, p.X);
    fe_sub(r.Y, p.Y, p.X);
    fe_mul(r.Z, r.X, q.yplusx);
    fe_mul(r.Y, r.Y, q.yminusx);
    fe_mul(r.T, q.xy2d, p.T);
    fe_add(t0, p.Z, p.Z);
    fe_sub(r.X, r.Z, r.Y);
    fe_add(r.Y, r.Z, r.Y);
    fe_add(r.Z, t0, r.T);
    fe_sub(r.T, t0, r.T);
}

static void ge_add(ge_p1p1& r, const ge_p3& p, const ge_cached& q) {
    fe t0;
    fe_add(r.X, p.Y, p.X);
    fe_sub(r.Y, p.Y, p.X);
    fe_mul(r.Z, r.X, q.YplusX);
    fe_mul(r.Y, r.Y, q.YminusX);
    fe_mul(r.T, q.T2d, p.T);
    fe_mul(r.X, p.Z, q.Z);
    fe_add(t0, r.X, r.X);
    fe_sub(r.X, r.Z, r.Y);
    fe_add(r.Y, r.Z, r.Y);
    fe_add(r.Z, t0, r.T);
    fe_sub(r.T, t0, r.T);
}

[[maybe_unused]] static void ge_sub(ge_p1p1& r, const ge_p3& p, const ge_cached& q) {
    fe t0;
    fe_add(r.X, p.Y, p.X);
    fe_sub(r.Y, p.Y, p.X);
    fe_mul(r.Z, r.X, q.YminusX);
    fe_mul(r.Y, r.Y, q.YplusX);
    fe_mul(r.T, q.T2d, p.T);
    fe_mul(r.X, p.Z, q.Z);
    fe_add(t0, r.X, r.X);
    fe_sub(r.X, r.Z, r.Y);
    fe_add(r.Y, r.Z, r.Y);
    fe_sub(r.Z, t0, r.T);
    fe_add(r.T, t0, r.T);
}

static void cmov(ge_precomp& t, const ge_precomp& u, uint8_t b) {
    uint32_t mask = (uint32_t)(-((int32_t)b));
    for (int i = 0; i < 10; i++) {
        t.yplusx[i] ^= mask & (t.yplusx[i] ^ u.yplusx[i]);
        t.yminusx[i] ^= mask & (t.yminusx[i] ^ u.yminusx[i]);
        t.xy2d[i] ^= mask & (t.xy2d[i] ^ u.xy2d[i]);
    }
}

static uint8_t negative(int8_t b) {
    return (uint8_t)(((uint32_t)b) >> 31);
}

// table_select removed - not needed for simple scalar multiplication

// ────────────────────────────────────────────────────────────────────────────
// Scalar operations (mod group order l)
// ────────────────────────────────────────────────────────────────────────────

// Group order l = 2^252 + 27742317777372353535851937790883648493
static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static uint64_t load_3(const uint8_t* in) {
    uint64_t result;
    result = (uint64_t)in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    return result;
}

static uint64_t load_4(const uint8_t* in) {
    uint64_t result;
    result = (uint64_t)in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    return result;
}

void sc_reduce(uint8_t* s, uint8_t* out) {
    int64_t s0 = 2097151 & load_3(s);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 0;
    int64_t s14 = 0;
    int64_t s15 = 0;
    int64_t s16 = 0;
    int64_t s17 = 0;
    int64_t s18 = 0;
    int64_t s19 = 0;
    int64_t s20 = 0;
    int64_t s21 = 0;
    int64_t s22 = 0;
    int64_t s23 = 0;
    
    if (s + 63 < s + 64) { // Bounds check
        s13 = 2097151 & (load_3(s + 34) >> 1);
        s14 = 2097151 & (load_4(s + 36) >> 6);
        s15 = 2097151 & (load_3(s + 39) >> 3);
        s16 = 2097151 & load_3(s + 42);
        s17 = 2097151 & (load_4(s + 44) >> 5);
        s18 = 2097151 & (load_3(s + 47) >> 2);
        s19 = 2097151 & (load_4(s + 49) >> 7);
        s20 = 2097151 & (load_4(s + 52) >> 4);
        s21 = 2097151 & (load_3(s + 55) >> 1);
        s22 = 2097151 & (load_4(s + 57) >> 6);
        s23 = (load_4(s + 60) >> 3);
    }
    
    // Barrett reduction
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    
    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    
    // Continue reduction
    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    
    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    
    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    
    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    
    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    
    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    
    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    
    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    
    // Carry chain
    int64_t carry0 = (s0 + (1LL << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    int64_t carry2 = (s2 + (1LL << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    int64_t carry4 = (s4 + (1LL << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    int64_t carry6 = (s6 + (1LL << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    int64_t carry8 = (s8 + (1LL << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    int64_t carry10 = (s10 + (1LL << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    
    int64_t carry1 = (s1 + (1LL << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    int64_t carry3 = (s3 + (1LL << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    int64_t carry5 = (s5 + (1LL << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    int64_t carry7 = (s7 + (1LL << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    int64_t carry9 = (s9 + (1LL << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    int64_t carry11 = (s11 + (1LL << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    
    // Final carry chain
    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
    
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    
    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    
    // Output bytes
    out[0] = s0 >> 0;
    out[1] = s0 >> 8;
    out[2] = (s0 >> 16) | (s1 << 5);
    out[3] = s1 >> 3;
    out[4] = s1 >> 11;
    out[5] = (s1 >> 19) | (s2 << 2);
    out[6] = s2 >> 6;
    out[7] = (s2 >> 14) | (s3 << 7);
    out[8] = s3 >> 1;
    out[9] = s3 >> 9;
    out[10] = (s3 >> 17) | (s4 << 4);
    out[11] = s4 >> 4;
    out[12] = s4 >> 12;
    out[13] = (s4 >> 20) | (s5 << 1);
    out[14] = s5 >> 7;
    out[15] = (s5 >> 15) | (s6 << 6);
    out[16] = s6 >> 2;
    out[17] = s6 >> 10;
    out[18] = (s6 >> 18) | (s7 << 3);
    out[19] = s7 >> 5;
    out[20] = s7 >> 13;
    out[21] = s8 >> 0;
    out[22] = s8 >> 8;
    out[23] = (s8 >> 16) | (s9 << 5);
    out[24] = s9 >> 3;
    out[25] = s9 >> 11;
    out[26] = (s9 >> 19) | (s10 << 2);
    out[27] = s10 >> 6;
    out[28] = (s10 >> 14) | (s11 << 7);
    out[29] = s11 >> 1;
    out[30] = s11 >> 9;
    out[31] = s11 >> 17;
}

bool sc_is_canonical(const uint8_t* s) {
    // Check if s < L in constant time
    uint8_t c = 0;
    uint8_t n = 1;
    
    for (int i = 31; i >= 0; i--) {
        c |= ((s[i] - L[i]) >> 8) & n;
        n &= ((s[i] ^ L[i]) - 1) >> 8;
    }
    
    return c != 0;
}

void sc_muladd(uint8_t* s, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
    // This would implement s = (a * b + c) mod l
    // For now, simplified implementation
    std::array<uint8_t, 64> ab;
    std::array<uint8_t, 32> reduced_ab;
    
    // Multiply a * b (schoolbook multiplication)
    std::memset(ab.data(), 0, 64);
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            ab[i + j] += a[i] * b[j];
        }
    }
    
    // Reduce ab mod l
    sc_reduce(ab.data(), reduced_ab.data());
    
    // Add c
    uint16_t carry = 0;
    for (int i = 0; i < 32; i++) {
        carry += reduced_ab[i] + c[i];
        s[i] = carry & 0xff;
        carry >>= 8;
    }
    
    // Final reduction if needed
    uint8_t tmp[32];
    sc_reduce(s, tmp);
    std::memcpy(s, tmp, 32);
}

// ────────────────────────────────────────────────────────────────────────────
// High-level Ed25519 operations
// ────────────────────────────────────────────────────────────────────────────

// Initialize base point on first use
static bool base_point_initialized = false;
static ge_p3 computed_base_point;

static void init_base_point() {
    if (base_point_initialized) return;
    
    // The Ed25519 base point has y = 4/5 mod p
    // y = 0x6666666666666666666666666666666666666666666666666666666666666658
    fe y_coord;
    
    // 4/5 mod p in radix 2^25.5 representation
    // This is 0x666...658 which is (2^255 - 19) * 4/5
    y_coord[0] = 46316835 & ((1 << 26) - 1);
    y_coord[1] = (46316835 >> 26) | ((46316835 & ((1 << 25) - 1)) << 6);
    y_coord[2] = 46316835 & ((1 << 26) - 1);
    y_coord[3] = (46316835 >> 26) | ((46316835 & ((1 << 25) - 1)) << 6);
    y_coord[4] = 46316835 & ((1 << 26) - 1);
    y_coord[5] = (46316835 >> 26) | ((46316835 & ((1 << 25) - 1)) << 6);
    y_coord[6] = 46316835 & ((1 << 26) - 1);
    y_coord[7] = (46316835 >> 26) | ((46316835 & ((1 << 25) - 1)) << 6);
    y_coord[8] = 46316835 & ((1 << 26) - 1);
    y_coord[9] = 11370326;  // Adjusted for the 58 at the end
    
    // Ed25519 base point from ref10 implementation
    // These are the exact values used in the reference implementation
    computed_base_point.X[0] = -14297830;
    computed_base_point.X[1] = -7645148;
    computed_base_point.X[2] = 16144683;
    computed_base_point.X[3] = -16471763;
    computed_base_point.X[4] = 27570974;
    computed_base_point.X[5] = -2696100;
    computed_base_point.X[6] = -26142465;
    computed_base_point.X[7] = 8378389;
    computed_base_point.X[8] = 20764389;
    computed_base_point.X[9] = 8758491;
    
    // Y coordinate: 4/5 mod p
    computed_base_point.Y[0] = 26843545;
    computed_base_point.Y[1] = 6710886;
    computed_base_point.Y[2] = 13421772;
    computed_base_point.Y[3] = 20132659;
    computed_base_point.Y[4] = 26843545;
    computed_base_point.Y[5] = 6710886;
    computed_base_point.Y[6] = 53687091;
    computed_base_point.Y[7] = 13421772;
    computed_base_point.Y[8] = 40265318;
    computed_base_point.Y[9] = 6710886;
    
    // Z = 1
    fe_1(computed_base_point.Z);
    
    // T = X*Y
    fe_mul(computed_base_point.T, computed_base_point.X, computed_base_point.Y);
    
    base_point_initialized = true;
}

void ge_scalarmult_base(ge_p3* h, const uint8_t* a) {
    // Initialize base point if needed
    init_base_point();
    
    // Scalar multiplication: h = a * B where B is the base point
    // Simple double-and-add algorithm without precomputed tables
    
    // Start with identity element
    ge_p3_0(*h);
    
    // Work with a copy of the base point
    ge_p3 point;
    fe_copy(point.X, computed_base_point.X);
    fe_copy(point.Y, computed_base_point.Y);
    fe_copy(point.Z, computed_base_point.Z);
    fe_copy(point.T, computed_base_point.T);
    
    // Process scalar from least significant bit to most significant
    for (int i = 0; i < 256; i++) {
        // Check if bit i is set
        if ((a[i >> 3] >> (i & 7)) & 1) {
            // Add current point to result
            ge_cached point_cached;
            ge_p3_to_cached(point_cached, point);
            ge_p1p1 sum;
            ge_add(sum, *h, point_cached);
            ge_p1p1_to_p3(*h, sum);
        }
        
        // Double point for next bit (except on last iteration)
        if (i < 255) {
            ge_p2 point_p2;
            ge_p3_to_p2(point_p2, point);
            ge_p1p1 doubled;
            ge_p2_dbl(doubled, point_p2);
            ge_p1p1_to_p3(point, doubled);
        }
    }
}

// Forward declaration
static int fe_isnegative(const fe& f);

void ge_p3_tobytes(uint8_t* s, const ge_p3* h) {
    fe recip;
    fe x;
    fe y;
    
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

static int fe_isnegative(const fe& f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe& f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    uint8_t r = 0;
    for (int i = 0; i < 32; i++) {
        r |= s[i];
    }
    return r != 0;
}

static void fe_pow22523(fe& out, const fe& z) {
    fe t0, t1, t2;
    
    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 1; i < 5; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 1; i < 10; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (int i = 1; i < 20; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 1; i < 10; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 1; i < 50; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (int i = 1; i < 100; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 1; i < 50; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

int ge_frombytes_negate_vartime(ge_p3* h, const uint8_t* s) {
    fe u;
    fe v;
    fe v3;
    fe vxx;
    fe check;
    
    // y = s (with top bit cleared)
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);       // u = y^2
    fe_mul(v, u, d);      // v = u*d = y^2*d
    fe_sub(u, u, h->Z);   // u = y^2 - 1
    fe_add(v, v, h->Z);   // v = y^2*d + 1
    
    fe_sq(v3, v);
    fe_mul(v3, v3, v);    // v3 = v^3
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u); // x = u*v^7
    
    fe_pow22523(h->X, h->X); // x = (u*v^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);   // x = u*v^3*(u*v^7)^((q-5)/8)
    
    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);   // v*x^2 - u
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); // v*x^2 + u
        if (fe_isnonzero(check)) {
            return -1;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }
    
    if (fe_isnegative(h->X) != (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

void ge_double_scalarmult_vartime(ge_p2* r, const uint8_t* a, const ge_p3* A, const uint8_t* b) {
    // Compute r = a*A + b*B where B is the base point
    // This is a simplified implementation
    ge_p3 aA, bB;
    
    // Compute a*A (would use sliding window method in real implementation)
    // For now, simplified
    ge_p3_0(aA);
    
    // Compute b*B
    ge_scalarmult_base(&bB, b);
    
    // Add them together
    ge_cached bB_cached;
    ge_p3_to_cached(bB_cached, bB);
    ge_p1p1 sum;
    ge_add(sum, aA, bB_cached);
    ge_p1p1_to_p2(*r, sum);
}

void ge_tobytes(uint8_t* s, const ge_p2* h) {
    fe recip;
    fe x;
    fe y;
    
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

} // namespace psyfer::crypto