# Reset
NC='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# Underline
UBlack='\033[4;30m'       # Black
URed='\033[4;31m'         # Red
UGreen='\033[4;32m'       # Green
UYellow='\033[4;33m'      # Yellow
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'      # Purple
UCyan='\033[4;36m'        # Cyan
UWhite='\033[4;37m'       # White

# Background
On_Black='\033[40m'       # Black
On_Red='\033[41m'         # Red
On_Green='\033[42m'       # Green
On_Yellow='\033[43m'      # Yellow
On_Blue='\033[44m'        # Blue
On_Purple='\033[45m'      # Purple
On_Cyan='\033[46m'        # Cyan
On_White='\033[47m'       # White

# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White

# Bold High Intensity
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White

# High Intensity backgrounds
On_IBlack='\033[0;100m'   # Black
On_IRed='\033[0;101m'     # Red
On_IGreen='\033[0;102m'   # Green
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White

print_Black () {
	MSG=$1
	echo "$Black$MSG$NC"
}

print_Red () {
	MSG=$1
	echo "$Red$MSG$NC"
}

print_Green () {
	MSG=$1
	echo "$Green$MSG$NC"
}

print_Yellow () {
	MSG=$1
	echo "$Yellow$MSG$NC"
}

print_Blue () {
	MSG=$1
	echo "$Blue$MSG$NC"
}

print_Purple () {
	MSG=$1
	echo "$Purple$MSG$NC"
}

print_Cyan () {
	MSG=$1
	echo "$Cyan$MSG$NC"
}

print_White () {
	MSG=$1
	echo "$White$MSG$NC"
}

print_BBlack () {
	MSG=$1
	echo "$BBlack$MSG$NC"
}

print_BRed () {
	MSG=$1
	echo "$BRed$MSG$NC"
}

print_BGreen () {
	MSG=$1
	echo "$BGreen$MSG$NC"
}

print_BYellow () {
	MSG=$1
	echo "$BYellow$MSG$NC"
}

print_BBlue () {
	MSG=$1
	echo "$BBlue$MSG$NC"
}

print_BPurple () {
	MSG=$1
	echo "$BPurple$MSG$NC"
}

print_BCyan () {
	MSG=$1
	echo "$BCyan$MSG$NC"
}

print_BWhite () {
	MSG=$1
	echo "$BWhite$MSG$NC"
}

print_UBlack () {
	MSG=$1
	echo "$UBlack$MSG$NC"
}

print_URed () {
	MSG=$1
	echo "$URed$MSG$NC"
}

print_UGreen () {
	MSG=$1
	echo "$UGreen$MSG$NC"
}

print_UYellow () {
	MSG=$1
	echo "$UYellow$MSG$NC"
}

print_UBlue () {
	MSG=$1
	echo "$UBlue$MSG$NC"
}

print_UPurple () {
	MSG=$1
	echo "$UPurple$MSG$NC"
}

print_UCyan () {
	MSG=$1
	echo "$UCyan$MSG$NC"
}

print_UWhite () {
	MSG=$1
	echo "$UWhite$MSG$NC"
}

print_Green "[*] ASDF"
