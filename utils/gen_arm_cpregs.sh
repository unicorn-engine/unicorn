if [ ! -d "./arm-doc" ]; then 
	mkdir ./arm-doc

	cd arm-doc
	wget https://developer.arm.com/-/media/developer/products/architecture/armv8-a-architecture/ARMv83A-SysReg-00bet4.tar.gz?la=en -O ARMv83A-SysReg-00bet4.tar.gz
	tar -xvf ARMv83A-SysReg-00bet4.tar.gz
	tar -xvf SysReg_v83A_xml-00bet4.tar.gz
	cd ..
fi
python ./arm-doc-parser.py ./arm-doc/SysReg_v83A_xml-00bet4 ../
