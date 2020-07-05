import fingerprinter.packetcrafter.packet_crafter as pc
import fingerprinter.cloudproviderdetection.cloudprovider_detection as cd
import sys

allowed_commands = ["os-fingerprinting", "cloudprovider-detection"]


def print_welcome_banner():
    print("\
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
          @################################@\n\
          @########                ########@\n\
          @########                ########@\n\
          @########        ################@\n\
          @########        ################@\n\
          @########        ################@\n\
          @########              ##########@\n\
          @########              ##########@\n\
          @########        ################@\n\
          @########        ################@\n\
          @########        ##Fingerprinter#@\n\
          @########        #######by#######@\n\
          @########        #####Philip#####@\n\
          @########        #####Marti######@\n\
          @######################v1.0######@\n\
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

    print("\nWelcome to Fingerprinter, a python program by Philip Marti (github.com/martiph).")
    print("You can either detect the cloudprovider of a given system or the operating system of a remote system.")


def print_help():
    print("Please enter one of the following commands:")
    for command in allowed_commands:
        print(command)
        if command == "os-fingerprinting":
            print("\t - this command is used to fingerprint a windows or ubuntu system")
        elif command == "cloudprovider-detection":
            print("\t - this command is used to detect if AWS or Azure is used to host the system")
    print("exit")
    print("\t - exits this application")


def parse_input():
    try:
        text = input(">")
        while text != "exit":
            if text not in allowed_commands:
                print_help()
                text = input(">")
            elif text == "os-fingerprinting":
                print("Please provide following information:")
                src_ip = input("Source IP-Address (usually your own): ")
                src_port = int(input("Source Port: "))
                dest_ip = input("Destination IP-Address (Address of target):")
                dest_port = input("Destination Port: ")
                pc.fingerprint(src_ip, src_port, dest_ip, dest_port)
            elif text == "cloudprovider-detection":
                print("Please provide the IP-Address of your target")
                target = input(">")
                cd.detect(target)
    except KeyboardInterrupt:
        sys.exit()


def main():
    print_welcome_banner()
    parse_input()


if __name__ == '__main__':
    main()
