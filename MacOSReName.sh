theSerial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')

sudo scutil --set ComputerName "AGC-$theSerial"
sudo scutil --set HostName "AGC-$theSerial"
sudo scutil --set LocalHostName "AGC-$theSerial"