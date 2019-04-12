#ifndef   _____GM_DEFINE___H____
#define   _____GM_DEFINE___H____


#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC�㷨X�������󳤶�
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC�㷨Y�������󳤶�
#define ECC_MAX_MODULUS_BITS_LEN 512		//ECC�㷨ģ������󳤶�

typedef  unsigned long ULONG;
typedef  char          CHAR;
typedef  unsigned char BYTE;


#define MAX_IV_LEN			32		//��ʼ����������󳤶�


#pragma pack(1)


/*
 *ECC��Կ�������ݿ�
 */
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

/*
 *ECC˽Կ�������ݿ�
 */
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

/*
 *ECC�������ݽṹ
 */
typedef struct Struct_ECCCIPHERBLOB{
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	HASH[32]; 
	ULONG	CipherLen;
	BYTE	Cipher[65]; //���ܹ淶�ж����Ciperֻ��һ���ֽڣ�ʵ��������64�ֽ�
} ECCCIPHERBLOB, *PECCCIPHERBLOB;


typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE	r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	s[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

//��ECC������Կ�Ա����ṹ
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;                  // ��ǰ�汾Ϊ 1
	ULONG ulSymmAlgID;              // �Գ��㷨��ʶ���޶�ECBģʽ
	ULONG ulBits;					// ������Կ�Ե���Կλ����
	BYTE cbEncryptedPriKey[64];     // ������Կ��˽Կ������
	ECCPUBLICKEYBLOB PubKey;        // ������Կ�ԵĹ�Կ
	ECCCIPHERBLOB ECCCipherBlob;    // �ñ�����Կ���ܵĶԳ���Կ���ġ�
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*
 *�����������
 */
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];			//��ʼ������MAX_IV_LENΪ��ʼ��������󳤶�
	ULONG	IVLen;					//��ʼ����ʵ�ʳ��ȣ����ֽڼ���
	ULONG	PaddingType;			//��䷽ʽ��0��ʾ����䣬1��ʾ����PKCS#5��ʽ�������
	ULONG	FeedBitLen;				//����ֵ��λ���ȣ����ֽڼ��㣬ֻ���OFB��CFBģʽ
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

/*
 *�ļ�����
 */
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];			//�ļ���
	ULONG	FileSize;				//�ļ���С
	ULONG	ReadRights;				//��Ȩ��
	ULONG	WriteRights;			//дȨ��
} FILEATTRIBUTE, *PFILEATTRIBUTE;

#pragma pack()


#endif //_____GM_DEFINE___H____