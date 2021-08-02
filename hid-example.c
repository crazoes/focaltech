// SPDX-License-Identifier: GPL-2.0

/* Linux */
#include <linux/types.h>
#include <linux/input.h>
#include <linux/hidraw.h>
#include <time.h>

#ifndef HIDIOCSFEATURE
#warning Please have your distro update the userspace kernel headers
#define HIDIOCSFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
#define HIDIOCGFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
#endif
#define HIDIOCGINPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0A, len)
#define HIDIOCSOUTPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0B, len)
#define HIDIOCGOUTPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0C, len)
#define HIDIOCSINPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x09, len)

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define WRITE_REQ_LEN 72
#define READ_REQ_LEN 6
#define READ_LEN 66

int fd;

unsigned char checksum(unsigned char *pData, unsigned char BytesNum)
{
	unsigned int i=0;
	unsigned char Checksum=0;
	for(i=0; i<BytesNum; i++)
	{
		Checksum ^= pData[i];
	}
	Checksum++;
	return Checksum;
}

static int submit_request(unsigned char *buf, int len)
{
	int i, ret;

	printf("[WRITE] ");
	for (i = 0; i < len; i++)
		printf("%hhx ", buf[i]);
	puts("\n");

	ret = write(fd, buf, len);
	if (ret < 0)
		return ret;
	return 0;
}

static int send_write_request(unsigned char cmd)
{
	unsigned char buf[WRITE_REQ_LEN + 1];
	unsigned char *message = &buf[1];
	unsigned char len = 0x5;	/* fixed len for non-data commands */
	int i = 0;

	/* First byte is not part of the message and must be zero. */
	buf[i] = 6;

	message[i++] = 0xff;
	message[i++] = 0xff;
	message[i++] = len;
	message[i++] = cmd;
	message[i++] = checksum(message, len - 1);
	for (; i < (WRITE_REQ_LEN+1) ; i++)
		message[i] = 0xff;

	return submit_request(buf, sizeof(buf)-9);
}

static int read_response()
{
	unsigned char buf[READ_LEN +1];

	memset(buf, 0x0, READ_LEN+1);
	buf[0]=0x6;
	int ret =ioctl(fd, HIDIOCGINPUT(64), buf);
	printf("read response %d\n", ret);

	return ret;

}

int main(int argc, char **argv)
{
	char *device = "/dev/hidraw0";
	int retry = 1;

	fd = open(device, O_RDWR|O_NONBLOCK);
	if (fd < 0) {
		perror("Unable to open device");
		return 1;
	}

	while (retry--) {
		if (send_write_request(0x40)) {
			perror("write 0x45");
		}
		sleep(1);
		read_response();


	}
	return 0;
}
