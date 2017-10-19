package simple3;

import java.io.IOException;

public class Class1 {

    public static void main(String[] args) {
        int c;

        try {
            /*
            c is just one byte or -1
            stdin is converted using utf-8
            For example, inserting this character:
            http://www.unicode.org/cgi-bin/GetUnihanData.pl?codepoint=2020C
            returns 4 integers: 240, 160, 136, 140
            and "normal" ascii characters return 1 integer
            */
            c = System.in.read();
            c++;
            /*
            write expects an int in the 0-255 range
            if higer % 256 is applied to the input
            */
            System.out.write(c);
            System.out.flush();
            boolean b = System.out.checkError();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
