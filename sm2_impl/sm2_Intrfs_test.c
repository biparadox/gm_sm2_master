#include "stdio.h"
#include "stdlib.h"
#include "sm2.h"
#include "tommath.h"



int test_Ecc_Intrfs_sig_veri()
{
	printf("\n********\n* Ecc interface signature and verify test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [57]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");
//	char rand_k[] = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
//	char dgst[]   = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76";
//	char pri_dA[] = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

	char rand_k[] = "F026AD9A7EB94401A800C8D8C3277E69972C7F3778ACE4D537012023EDFB69FF";
	char dgst[]   = "3854C463FA3F73783621B1CE4EF83F7C78048AAC79B221FCDD290866CC131174";
	char pri_dA[] = "C242939DDAB6FCC07B6676C07D2DC117EC68A09142C25C008630B9756786162D";
	char p1[]     = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

	mp_int mp_Xg, mp_Yg, mp_rx, mp_ry, mp_p, mp_a, mp_rand_k;
	mp_int mp_r,  mp_s, mp_dgst,  mp_Pri_dA,  mp_n;
	mp_int mp_XA,  mp_YA;

	int ret = 0;
	mp_init_multi(&mp_Xg, &mp_Yg, &mp_rx, &mp_ry, &mp_p, &mp_a, 
		&mp_rand_k, &mp_r, &mp_s, &mp_dgst, &mp_Pri_dA, &mp_n, &mp_XA, &mp_YA,NULL);

	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
//	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	ret = mp_read_radix(&mp_p, (char *) p1, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_n, (char *) param_n, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_dgst, (char *) dgst, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Pri_dA, (char *) pri_dA, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_rand_k, (char *) rand_k, 16);
	CHECK_RET(ret);

	printf("...params are...\n");
	printf("p=");
	MP_print(&mp_p);
	printf("a=");
	MP_print(&mp_a);
	printf("n=");
	MP_print(&mp_n);
	printf("Xg=");
	MP_print(&mp_Xg);
	printf("Yg=");
	MP_print(&mp_Yg);
	printf("dA=");
	MP_print(&mp_Pri_dA);
	printf("rand=");
	MP_print(&mp_rand_k);
	
	ret = Ecc_Sm2_sign(&mp_r, &mp_s, &mp_dgst, &mp_rand_k, &mp_Pri_dA, &mp_Xg, &mp_Yg, 
				 &mp_a, &mp_p, &mp_n);	
	if (ret == 0)
	{
		printf("...signature ok...\n");
	}
	else
	{
		printf("...signature failed!\n");
		CHECK_RET(ret);
	}

	printf("...signature data:\n");
	printf("r=");
	MP_print(&mp_r);
	printf("s=");
	MP_print(&mp_s);
	
	// compute public key
	ret = Ecc_points_mul(&mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_Pri_dA, &mp_a, &mp_p);
	CHECK_RET(ret);

	printf("...public key:\n");
	printf("XA=");
	MP_print(&mp_XA);
	printf("YA=");
	MP_print(&mp_YA);

	printf("......verify signature...\n");
	ret = Ecc_Sm2_verifySig(&mp_r, &mp_s, &mp_dgst, &mp_XA, 
		&mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_p, &mp_n);
	if (ret == 0)
	{
		printf("\nverify ok!\n");
	}
	else
	{
		printf("\nverify failed!\n");
		CHECK_RET(ret);
	}

	
END:
    mp_clear_multi(&mp_Xg, &mp_Yg, &mp_rx, &mp_ry, &mp_p, &mp_a, 
		&mp_rand_k, &mp_r, &mp_s, &mp_dgst, &mp_Pri_dA, &mp_n, &mp_XA, &mp_YA,NULL);
	printf("********\n* test end\n********\n");
	return ret;
}



int test_GM_encryption_and_decryption()
{
	printf("\n********\n* GM sm2 asym encryption and decryption test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [90]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");
	unsigned char buff[64] = {0};unsigned long buffLen = 64;
	unsigned char prikeyBuff[200] = {0};unsigned long priLen = 200;
	int ret = 0;
	char plain[] = "67";
	unsigned char encData[1000] = {0};
	unsigned long encLen = 1000;
	unsigned char decData[1000] = {0};
	unsigned long decLen = 1000;

	char  pubkey_B_XY[] = "435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
	char prikey[] = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
	ret = hexCharStr2unsignedCharStr(pubkey_B_XY, strlen(pubkey_B_XY), 0, buff, &buffLen);
	CHECK_RET(ret);
	ret = hexCharStr2unsignedCharStr(prikey, strlen(prikey),0, prikeyBuff, &priLen);
	CHECK_RET(ret);
	
	printf("...public key\n");
	printf("XB=");
	BYTE_print(buff, 32);
	printf("YB=");
	BYTE_print(buff+32, 32);

	printf("...plain text:\n%s\n", plain);
	ret = GM_SM2Encrypt(encData, &encLen, (unsigned char *)plain, strlen(plain), buff, buffLen);
	CHECK_RET(ret);
	ret = GM_SM2Decrypt(decData, &decLen, encData, encLen, prikeyBuff, priLen);
	CHECK_RET(ret);
	printf("\n...decdata:%s\n", decData);
END:

	printf("********\n* test end\n********\n");
	return ret;
}



int test_gen_SM2_GM_keypair()
{
	printf("\n********\n* GM sm2 keypair generation test\n********\n\n");

	unsigned char buff[64] = {0};unsigned long buffLen = 64;
	unsigned char prikeyBuff[200] = {0};unsigned long priLen = 200;
	int ret = 0;
	ret = GM_GenSM2keypair(prikeyBuff, &priLen, buff);
	CHECK_RET(ret);

	printf("...pubkey (XA,YA):\n");
	printf("XA=");
	BYTE_print(buff, 32);
	printf("YA=");
	BYTE_print(buff+32, 32);
	printf("...prikey dA:\n");
	BYTE_print(prikeyBuff, priLen);
	
END:
	printf("********\n* test end\n********\n");
	return ret;

}

int main()
{
	int ret=0;
	ret = test_Ecc_Intrfs_sig_veri();
//	ret = test_GM_encryption_and_decryption();
//	ret = test_gen_SM2_GM_keypair();

	return ret;
}
