package simple4;

import java.io.IOException;

public class Class1 {

    public static void main(String[] args) {
        int c;

        try {
            c = System.in.read();
            if(c=='F'){
                System.out.write('W');
            }else{
                System.out.write('L');
            }
            System.out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
