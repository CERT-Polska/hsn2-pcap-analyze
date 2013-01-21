DEBIAN_DIST=experimental
HSN2_COMPONENT=pcap-analyze

PKG=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_all
package: clean
	mkdir -p $(PKG)/opt/hsn2/pcap-analyze
	mkdir -p $(PKG)/etc/hsn2/pcap-analyze
	mkdir -p $(PKG)/etc/wireshark
	mkdir -p $(PKG)/etc/init.d
	mkdir -p $(PKG)/DEBIAN
	cp *.py $(PKG)/opt/hsn2/pcap-analyze/
	cp debian/init.lua $(PKG)/etc/wireshark
	cp debian/initd $(PKG)/etc/init.d/hsn2-pcap-analyze
	cp debian/pcap-analyze.conf $(PKG)/etc/hsn2/pcap-analyze/pcap-analyze.conf
	cp debian/pcap-analyze-whitelist.conf $(PKG)/etc/hsn2/pcap-analyze/pcap-analyze-whitelist.conf
	cp debian/control $(PKG)/DEBIAN
	cp debian/conffiles $(PKG)/DEBIAN
	sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKG)/DEBIAN/control
	sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKG)/DEBIAN/control
	fakeroot dpkg -b $(PKG)
	
clean:
	rm -rf $(PKG)