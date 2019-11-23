
#define PGIN_RMID	0xF1AD1966
#define PGIN_STOP	0xFFFFFFFE

#define ITER_PASS	0x1
#define ITER_STOP	0x2

struct pgin_request
{
	__u32	rmid;
	__u32	size;
	__u64	index;
	__u64	handle;
};

struct pgin_reply
{
	__u32	rmid;
	__u32	error;
	__u64	handle;
};
