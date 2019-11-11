//Decryption File
#include <stdio.h>
#include <string.h>
#include <errno.h>
unsigned short ax,bx,cx,dx,si,tmp,x1a2,x1a0[16],res,i,inter,cfc,cfd,compte;
unsigned char cle[32];
unsigned char buff[32];
short c;
int c1,count;
short d,e;
FILE *in,*out;

void fin() {

    /*  erase all variables */
    for (compte=0; compte<=31; compte++) {
        cle[compte]=0;
    }
    ax=0;
    bx=0;
    cx=0;
    dx=0;
    si=0;
    tmp=0;
    x1a2=0;
    x1a0[0]=0;
    x1a0[1]=0;
    x1a0[2]=0;
    x1a0[3]=0;
    x1a0[4]=0;
    res=0;
    i=0;
    inter=0;
    cfc=0;
    cfd=0;
    compte=0;
    c=0;
}

void assemble() {

    x1a0[0]= ( cle[0]*256 )+ cle[1];
    code();
    inter=res;

    x1a0[1]= x1a0[0] ^ ( (cle[2]*256) + cle[3] );
    code();
    inter=inter^res;

    x1a0[2]= x1a0[1] ^ ( (cle[4]*256) + cle[5] );
    code();
    inter=inter^res;

    x1a0[3]= x1a0[2] ^ ( (cle[6]*256) + cle[7] );
    code();
    inter=inter^res;

    x1a0[4]= x1a0[3] ^ ( (cle[8]*256) + cle[9] );
    code();
    inter=inter^res;

    x1a0[5]= x1a0[4] ^ ( (cle[10]*256) + cle[11] );
    code();
    inter=inter^res;

    x1a0[6]= x1a0[5] ^ ( (cle[12]*256) + cle[13] );
    code();
    inter=inter^res;

    x1a0[7]= x1a0[6] ^ ( (cle[14]*256) + cle[15] );
    code();
    inter=inter^res;

    x1a0[8]= x1a0[7] ^ ( (cle[16]*256) + cle[17] );
    code();
    inter=inter^res;

    x1a0[9]= x1a0[8] ^ ( (cle[18]*256) + cle[19] );
    code();
    inter=inter^res;

    x1a0[10]= x1a0[9] ^ ( (cle[20]*256) + cle[21] );
    code();
    inter=inter^res;

    x1a0[11]= x1a0[10] ^ ( (cle[22]*256) + cle[23] );
    code();
    inter=inter^res;

    x1a0[12]= x1a0[11] ^ ( (cle[24]*256) + cle[25] );
    code();
    inter=inter^res;

    x1a0[13]= x1a0[12] ^ ( (cle[26]*256) + cle[27] );
    code();
    inter=inter^res;

    x1a0[14]= x1a0[13] ^ ( (cle[28]*256) + cle[29] );
    code();
    inter=inter^res;

    x1a0[15]= x1a0[14] ^ ( (cle[30]*256) + cle[31] );
    code();
    inter=inter^res;

    i=0;
}

int code()
{
    dx=x1a2+i;
    ax=x1a0[i];
    cx=0x015a;
    bx=0x4e35;

    tmp=ax;
    ax=si;
    si=tmp;

    tmp=ax;
    ax=dx;
    dx=tmp;

    if (ax!=0) {
        ax=ax*bx;
    }

    tmp=ax;
    ax=cx;
    cx=tmp;

    if (ax!=0) {
        ax=ax*si;
        cx=ax+cx;
    }

    tmp=ax;
    ax=si;
    si=tmp;
    ax=ax*bx;
    dx=cx+dx;

    ax=ax+1;

    x1a2=dx;
    x1a0[i]=ax;

    res=ax^dx;
    i=i+1;
    return 0;
}
int main(int argc,char* argv[]) {
    si=0;
    x1a2=0;
    i=0;

    if(argc!=3) {
        errno=EINVAL;
        perror("Bad Arguments");
        return errno;
    }

    /* ('abcdefghijklmnopqrstuvwxyz012345') is the default password used*/
    /* if the user enter a key < 32 characters, characters of the default */
    /* password will be used */

    strcpy(cle,"abcdefghijklmnopqrstuvwxyz01234");

    printf ("PC1 Cipher 256 bits \nDECRYPT file\n");
    printf("Enter a 32 character password:");
    scanf("%s",buff);

// for excess charecters
    if (strlen(buff)>32) {
        count=32;
    } else {
        count=strlen(buff);
    }
//if charecters less than 32
    for (c1=0; c1<count; c1++) {
        cle[c1]=buff[c1];
    }
//if files do not open  
    if ((in=fopen(argv[1],"rb")) == NULL) {
        printf("\nError reading file!\n");
        fin();
    }

    if ((out=fopen(argv[2],"wb")) == NULL) {
        printf("\nError writing file!\n");
        fin();
    }

//Reading the file
    while ( (d=fgetc(in)) != EOF) 
    {

        e=fgetc(in); 

        d=d-0x25; /* retrieve the 4 bits from the first letter */
        d=d<<4;

        e=e-0x25; /* retrieve the 4 bits from the second letter */
        c=d+e; /* 4 bits of the first letter + 4 bits of the second = 8 bits */

        assemble();
        cfc=inter>>8;
        cfd=inter&255; /* cfc^cfd = random byte */

 
        c = c ^ (cfc^cfd);

        for (compte=0; compte<=31; compte++)
        {
            /* we mix the plaintext byte with the key */
            cle[compte]=cle[compte]^c;
        }

        fputc(c,out); /* we write the decrypted byte in the file  */
    }
    fclose (in);
    fclose (out);
    fin();
    return 0;
}


