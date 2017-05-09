int main(int argc, char **argv)
{

    argc -= 1;

    if (argc == 0)
            return 0;
    else
    {
            switch (argc)
            {
                    case 1:
                            return 1;
                    default:
                            return 2;
            }
    }
}
