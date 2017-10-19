package crackme1;

import java.io.IOException;

public class Class1 {

    public static void win(){
        System.out.write('W');
        System.out.flush();
    }

    public static void fail(){
        System.out.write('L');
        System.out.flush();
        System.exit(-1);
    }


    public static void main(String[] args) {
        int c1=0;
        int c2=0;
        int c3=0;
        int c4=0;
        int c5=0;
        int c6=0;
        int c7=0;
        int c8=0;
        int c9=0;
        int c10=0;
        int v1,v2,v3,v4,v5;

        try {
            // JaV$!sB4D!
            c1 = System.in.read();
            c2 = System.in.read();
            c3 = System.in.read();
            c4 = System.in.read();
            c5 = System.in.read();
            c6 = System.in.read();
            c7 = System.in.read();
            c8 = System.in.read();
            c9 = System.in.read();
            c10 = System.in.read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(c1!='J'){
            fail();
        }

        v1 = (c2<<8)+c3;
        if(v1!=0x6156){
            fail();
        }

        v2 = c4*3214+c5*3;
        if(v2!=115803){
            fail();
        }

        if(c6>>1!=57){
            fail();
        }
        if(c6%2==0){
            fail();
        }

        v3 = (c7<<8)+c8;
        v4 = v3*v3 - 16938*v3 - 169480;
        if(v4!=0){
            fail();
        }
        if(v3<0){
            fail();
        }

        if(c9>70){
            fail();
        }
        if(c9<65){
            fail();
        }
        if((c9-61)%5!=2){
            fail();
        }

        v5 = c1+c2+c3+c4+c5+c6+c7+c8+c9+c10;
        if(v5!=660){
            fail();
        }
        win();
    }
}
