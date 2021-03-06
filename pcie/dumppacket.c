
// This program dumps a file produced by:
//     xbsvutil tlp /dev/fpga0 >testdata.dat
//

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define LINE_LENGTH 100
static char *data;
static char *datap;
static off_t size;

int gethex(char *data, int len)
{
    int ret = 0;
    while(len--) {
        ret = ret << 4;
        unsigned char ch = *data++;
        if (ch >= '0' && ch <= '9')
            ret |= ch - '0';
        else if (ch >= 'a' && ch <= 'f')
            ret |= ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F')
            ret |= ch - 'A' + 10;
        else
            printf("bogus character '%x'\n", ch);
    }
    return ret;
}
int get_next_line(unsigned char *buf, int buffer_len)
{
    unsigned char *bufp;
    while(1) {
        bufp = buf;
        while(datap < data+size && *datap++ != '\n' && bufp < buf + buffer_len - 1)
            *bufp++ = *(datap-1);
        *bufp = 0;
        if (strlen(buf) > 0 && strncmp(buf, "00000000", 8))
            break;
    }
    return bufp - buf;
}
void memdump(unsigned char *p, int len, char *title)
{
int i;

    i = 0;
    while (len > 0) {
        if (!(i & 0xf)) {
            if (i > 0)
                printf("\n");
            printf("%s: ",title);
        }
        printf("%02x ", *p++);
        i++;
        len--;
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    char lineitem[LINE_LENGTH];
    int fd = open("testdata.dat", O_RDONLY);
    int len;

    if (fd == -1) {
        printf("testdata.dat not found\n");
        return -1;
    }
    size = lseek(fd, 0, SEEK_END);
    data = (char *)malloc(size);
    datap = data;
    lseek(fd, 0, SEEK_SET);
    read(fd, data, size);
    close(fd);

    int i = 0;
    while(datap < data+size) {
        len = get_next_line(lineitem, sizeof(lineitem));
        char seqno[9];
        memcpy(seqno, lineitem, 8);
        seqno[8] = 0;

        char *dataline = &lineitem[8];
        int portnum = gethex(&dataline[0], 2) >> 1;
        int tlpsof = gethex(&dataline[1], 1) & 1;
        int pkttype = gethex(&dataline[8], 2) & 0x1f;
        char *foo;
        if (tlpsof == 0)
            foo = "cc";
        else if (pkttype == 10)
            foo = "pp";
        else
            foo = "qq";
        if (portnum == 4)
            printf("RX%s: ", foo);
        else if (portnum == 8)
            printf("TX%s: ", foo);
        else
            printf("____: ");
        printf("JJ %s %s\n", seqno, dataline);
    }
    return 0;
}
