#include <pbc.h>
#include <pbc/pbc_test.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// Number of cycle calculations
#define N_ATTR 3000
#define S_ATTR 100

// tp：Bilinear pairing
// tm：Scalar addition
// ta：Scalar multiplication
// th：General Hash
// tmtp: Map-to-point hash


int main(int argc, char **argv)
{
    pairing_t pairing;
    char param[1024];
    FILE *fp = fopen("a.param", "r");
    size_t count_param = fread(param, 1, 1024, fp);
    fclose(fp);
    pairing_init_set_buf(pairing, param, count_param);
    int length;

    if(!pairing_is_symmetric(pairing))
    {
        fprintf(stderr,"only works with symmetric pairing \n");
        exit(1);
    }
    element_t zp_a, zp_b, zp_c, g1_P, g2_P, gt_P, hash, Q;

    element_init_G1(g1_P, pairing);
    element_init_G1(g2_P, pairing);
    element_init_GT(gt_P, pairing);
    element_init_Zr(zp_a, pairing);
    element_init_Zr(zp_b, pairing);
    element_init_Zr(zp_c, pairing);
    element_init_Zr(hash, pairing);
    element_init_G1(Q, pairing);

    element_random(g1_P);
    //element_random(g2_P);
    element_random(gt_P);
    element_random(zp_a);
    element_random(zp_b);
    element_random(zp_c);
    element_random(Q);

    double t0 = 0.0;
    double t1 = 0.0;
    double tp = 0.0;
    double tm = 0.0;
    double ta = 0.0;
    double th = 0.0;
    double tmtp = 0.0;
    double t_total = 0.0;

    //Time cost for Tp
    for (int i = 0; i < 1000; i++)
    {
        /* code */
        t0 = pbc_get_time();//seconds
        pairing_apply(gt_P, g1_P, g1_P, pairing);
        t1 = pbc_get_time();
        tp = t1 - t0;
        t_total += tp;
    }
    printf("Average time of 1000 Tp: %6f ms\n", tp*1000);

    //Time cost for Tm
    for (int i = 0; i < 1000; i++)
    {
        /* code */
        t0 = pbc_get_time();//seconds
        element_mul_zn(g2_P, g1_P, zp_a);
        t1 = pbc_get_time();
        tm = t1 - t0;
        t_total += tm;
    }
    printf("Average time of 1000 Tm: %6f ms\n", tm*1000);

    //Time cost for Ta
    for (int i = 0; i < 1000; i++)
    {
        /* code */
        t0 = pbc_get_time();//seconds
        element_add(g2_P, g1_P, g1_P);
        t1 = pbc_get_time();
        ta = t1 - t0;
        t_total += ta;
    }
    printf("Average time of 1000 Ta: %6f ms\n", ta*1000);

    //Time cost for Th
    t_total = 0.0;
    for (int i = 0; i < 1000; i++)
    {
        /* code */
        t0 = pbc_get_time();//seconds
        element_from_hash(hash, (void *)"ABCDEF", 6);
        t1 = pbc_get_time();
        th = t1 - t0;
        t_total += th;
    }
    printf("Average time of 1000 Th: %6f ms\n", t_total/1000*1000);

    //Time cost for Tmtp
    t_total = 0.0;
    for (int i = 0; i < 1000; i++)
    {
        /* code */
        t0 = pbc_get_time();//seconds
        element_from_hash(Q, (void *)"ABCDEF", 6);
        t1 = pbc_get_time();
        tmtp = t1 - t0;
        t_total += tmtp;
    }
    printf("Average time of 1000 Tmtp: %6f ms\n", t_total/1000*1000);

   
    double tOur = 0.0;
    double tGong = 0.0;
    double tXiong = 0.0;
    double tLiu1 = 0.0;
    double tXu = 0.0;
    double tXie = 0.0;
    double tDeng = 0.0;
    double tLiu2 = 0.0;

printf("------Time cost of signing and verifying a single signature -------\n");
printf("Deng's scheme: %6f ms | - \n", (tm*3 + ta)*1000);
printf("Xie's scheme: %6f ms | %6f ms \n", (tm + ta)*1000, (3*tm + 2*ta + th)*1000);
printf("Xu's scheme: %6f ms | %6f ms \n", (tmtp + 2*tm + ta + 2*th)*1000, (3*tp + 2*tmtp + 2*tm + ta + 2*th)*1000);    
printf("Liu1's scheme: %6f ms | %6f ms \n", (2*tm + 3*th)*1000, (4*tm + 3*ta + 3*th)*1000); 
printf("Xiong's scheme: %6f ms | %6f ms \n", (2*tm + th)*1000, (2*tm + ta + th)*1000); 
printf("Gong's scheme: %6f ms | %6f ms \n", (tm + 3*th)*1000, (4*tm + 2*ta + 3*th)*1000); 
printf("Liu2's scheme: %6f ms | %6f ms \n", (tm + th)*1000, (5*tm + 4*ta)*1000); 
printf("Our scheme: %6f ms | %6f ms \n", (tm + th)*1000, (2*tm + 3*ta + th)*1000); 


printf("------Aggregate verification time cost for %d signatures -------\n", N_ATTR);


//Deng's scheme
    t0 = pbc_get_time();//seconds
    pairing_apply(gt_P, g1_P, g1_P, pairing);
    pairing_apply(gt_P, g1_P, g1_P, pairing);
    element_mul_zn(g2_P, g1_P, zp_a);
    element_mul_zn(g2_P, g1_P, zp_a);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKkijuhgrdghgfjtrfyjvghjf", 45);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKfloeujhgtysnchgtskoliuh", 45);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tDeng = t1 - t0 - ta;
    printf("Aggregate verification time cost of Deng's scheme: %6f ms\n", tDeng*1000);

//Xie's scheme
    t0 = pbc_get_time();//seconds
    element_add(g2_P, g1_P, g1_P);
    element_add(g2_P, g1_P, g1_P);
    element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKfloeujhgtysnchgtskoliuh", 45);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKkijuhgrdghgfjtrfyjvghjf", 45);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKfloeujhgtysnchgtskoliuh", 45);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tXie = t1 - t0;
    printf("Aggregate verification time cost of Xie's scheme: %6f ms\n", tXie*1000);


//Xu's scheme
    t0 = pbc_get_time();//seconds
    pairing_apply(gt_P, g1_P, g1_P, pairing);
    pairing_apply(gt_P, g1_P, g1_P, pairing);
    pairing_apply(gt_P, g1_P, g1_P, pairing);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        element_from_hash(Q, (void *)"ABCDEF", 6);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKkijuhgrdghgfjtrfyjvghjf", 45);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKfloeujhgtysnchgtskoliuh", 45);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tXu = t1 - t0 -2*ta;
    printf("Aggregate verification time cost of Xu's scheme: %6f ms\n", tXu*1000);
    
//Liu1's scheme
    t0 = pbc_get_time();//seconds
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKkijuhgrdghgfjtrfyjvghjf", 45);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKfloeujhgtysnchgtskoliuh", 45);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKpoiuyhklpudmssljdmkdkdl", 45);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tLiu1 = t1 - t0;
    printf("Aggregate verification time cost of Liu1's scheme: %6f ms\n", tLiu1*1000);


//Xiong's scheme
    t0 = pbc_get_time();//seconds
    element_mul_zn(g2_P, g1_P, zp_a);
    element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKasdfghjkloiuytrewqasdfg",45 );
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJKnjibhuvgtcdefrqasxcdewq", 45);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tXiong = t1 - t0;
    printf("Aggregate verification time cost of Xiong's scheme: %6f ms\n", (tXiong-ta)*1000);

//Gong's scheme
    t0 = pbc_get_time();//seconds
    element_mul_zn(g2_P, g1_P, zp_a);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tGong = t1 - t0;
    printf("Aggregate verification time cost of Gong's scheme: %6f ms\n", tGong*1000);


    //Liu2's scheme
    t0 = pbc_get_time();//seconds
    element_mul_zn(g2_P, g1_P, zp_a);
    element_mul_zn(g2_P, g1_P, zp_a);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tLiu2 = t1 - t0 - ta;
    printf("Aggregate verification time cost of Liu2's scheme: %6f ms\n", tLiu2*1000);

    //Our's scheme
    t0 = pbc_get_time();//seconds
    element_mul_zn(g2_P, g1_P, zp_a);
    for (int i = 0; i < N_ATTR; i++)
    {
        /* code */
        
        element_from_hash(hash, (void *)"CJDSKHJHFKSBSJKFKBBFJK", 22);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_add(g2_P, g1_P, g1_P);
        element_mul_zn(g2_P, g1_P, zp_a);
        element_mul_zn(g2_P, g1_P, zp_a);

    }
    t1 = pbc_get_time();
    tOur = t1 - t0 ;
    printf("Aggregate verification time cost of Our's scheme: %6f ms\n", (tOur-ta)*1000);

    element_clear(zp_a);
    element_clear(zp_b);
    element_clear(zp_c);
    element_clear(g1_P);
    element_clear(g2_P);
    element_clear(gt_P);
    element_clear(hash);
    element_clear(Q);
    pairing_clear(pairing);

    return 0;

}