retentionDays=90
currentUser=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
currentUserID="$(/usr/bin/id -u $currentUser)"
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)"

#Status of the 'all_max' setting for the 'install.log' file - > 90 Day
installRetention="$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')"
if [[ "$installRetention" = "" ]]; then
    mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
    sed '$s/$/ ttl=90/' /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
    chmod 644 /etc/asl/com.apple.install
    chown root:wheel /etc/asl/com.apple.install
else
if [[ "$installRetention" -ne "$retentionDays" ]]; then
    mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
    sed "s/"ttl=$installRetention"/"ttl=$retentionDays"/g" /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
    chmod 644 /etc/asl/com.apple.install
    chown root:wheel /etc/asl/com.apple.install
fi
fi

#Status of the 'rotate' setting for the 'install.log' file -> rotate=utc
mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
sed "s/"rotate=seq"/"rotate=utc"/g" /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
chmod 644 /etc/asl/com.apple.install
chown root:wheel /etc/asl/com.apple.install

#Status of the 'expire-after' setting for audit logs - > 90 Day
mv /etc/security/audit_control /etc/security/audit_control_old
sed "s/"flags:lo,aa"/"flags:lo,ad,fd,fm,-all"/g" /etc/security/audit_control_old > /etc/security/audit_control
chmod 644 /etc/security/audit_control
chown root:wheel /etc/security/audit_control
/usr/bin/sed -i.bak 's/^expire-after.*/expire-after:'$retentionDays'd/' /etc/security/audit_control
/usr/sbin/audit -s

#Status of the 'auditd' service -> Enable
checkAuditd="$(launchctl list | grep com.apple.auditd)"
if [[ "$checkAuditd" = "" ]]; then
/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
fi

#Library Validation -> Enable
defaults write /Library/Preferences/com.apple.security.librarayvalidation.plist DisableLibraryValidation -bool false

#Secure Home Folders -> 711
IFS=$'\n'
for userDirs in $( find /Users -mindepth 1 -maxdepth 1 -type d | grep -v "Shared" | grep -v "Guest" ); do
    #chmod og-rwx "$userDirs"
    chmod a+rwx,g-rw,o-rw "$userDirs"
done
chmod a+rwx,g-rw,o-rw /var/root
chmod a+rwx,g-rw,o-rw /private/var/root

#Status of the 'highstandbythreshold' setting -> 9
pmset -a highstandbythreshold 9

/usr/libexec/PlistBuddy -c "Delete :NAT:AirPort:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
/usr/libexec/PlistBuddy -c "Add :NAT:AirPort:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
/usr/libexec/PlistBuddy -c "Delete :NAT:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
/usr/libexec/PlistBuddy -c "Add :NAT:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
/usr/libexec/PlistBuddy -c "Delete :NAT:PrimaryInterface:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
/usr/libexec/PlistBuddy -c "Add :NAT:PrimaryInterface:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist

#Status of the 'Internet Sharing (NAT)' setting -> Disable
cat > /Library/LaunchDaemons/sysctl.plist << EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>sysctl</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/sbin/sysctl</string>
			<string>net.inet.ip.forwarding=0</string>
		</array>
		<key>WatchPaths</key>
		<array>
			<string>/Library/Preferences/SystemConfiguration</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
	</dict>
</plist>
EOF

if [ $(/bin/launchctl list | grep sysctl | awk '{ print $NF }') = "sysctl" ];then
    /bin/launchctl unload /Library/LaunchDaemons/sysctl.plist
fi
/bin/launchctl load /Library/LaunchDaemons/sysctl.plist

#Status of the 'DVD or CD Sharing' setting -> Disable
checkODSAgent="$(launchctl list | grep com.apple.ODSAgent)"
if [[ "$checkODSAgent" != "" ]]; then
/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
fi

#Status of the 'Remote Apple Events' setting -> Disable
/usr/sbin/systemsetup -setremoteappleevents off

#PolicyBannerText="CIS mandated Login Window banner"
echo "
User Access Agreement - ข้อตกลงการใช้งานตามนโยบายของบริษัท Ascend Group, ระบบคอมพิวเตอร์นี้สำหรับผู้ใช้งานที่มีสิทธิปฏิบัติงานในธุรกิจของบริษัทเท่านั้น, ผู้บริหารระบบจะทำการตรวจสอบและเก็บข้อมูลการใช้งานของผู้ใช้ที่ล่วงละเมิดสิทธิ, การใช้งาน หรือปฏิบัติหน้าที่เกินกว่าสิทธิที่ได้รับ ห้ามแก้ไขหรือติดตั้งระบบปฏิบัติการโดยพลการ, หากท่านยอมรับการตรวจสอบดังกล่าว กรุณากดปุ่ม Accept เพื่อดำเนินการต่อไป,
***************************************************************************************
This system is intended to be used solely by authorized users in the course of, legitimate corporate business. Users are monitored to the extent necessary to, properly administer the system , to identify unauthorized users or users operating, beyond their proper authority, and to investigate improper access or use., Do not modify or install the operating system by yourself., By accessing this system, you are consenting to this monitoring.,

IT Productivity, 
Phone: 02-0168600 #8899, 
Email: Supportcenter1@ascendcorp.com" > "/Library/Security/PolicyBanner.txt"
/bin/chmod 755 "/Library/Security/PolicyBanner."* 

#Set Password policies
pwpolicy -clearaccountpolicies  
pwpolicy -setglobalpolicy "maxFailedLoginAttempts=5 minChars=8 requiresNumeric=1 requiresAlpha=1 requiresSymbol=1 usingHistory=10 usingExpirationDate=1 maxMinutesUntilChangePassword=129600"
pwpolicy -u "ebiz-admin" -clearaccountpolicies  
pwpolicy -u "ebiz-admin" -setpolicy "usingHistory=0 usingExpirationDate=1 maxMinutesUntilChangePassword=5256000"

#Set SSH for admin
dseditgroup com.apple.access_ssh
dseditgroup -o create -q com.apple.access_ssh
dseditgroup -o edit -a admin -t group com.apple.access_ssh
/bin/launchctl load -w /System/Library/LaunchDaemons/ssh.plist
systemsetup -setremotelogin on

#Set /private/tmp for Tunnelblick"
chmod 01777 /private/tmp