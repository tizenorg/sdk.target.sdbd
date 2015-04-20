Name:       sdbd
Version:    2.2.25
Release:    1
License:    Apache-2.0
Summary:    SDB daemon
Group:      System/Utilities
Source0:    %{name}-%{version}.tar.gz
Source1001:    sdbd_device.service
Source1002:    sdbd_emulator.service

BuildRequires: capi-system-info-devel
BuildRequires: vconf-devel
BuildRequires: smack-devel
#BuildRequires: sec-product-features
BuildRequires: pkgconfig(vasum)
BuildRequires: pkgconfig(glib-2.0)
Requires(post): pkgmgr
Requires(post): pkgmgr-server
Requires(post): wrt
Requires(post): aul
Requires: default-files-tizen
Requires: sys-assert
Requires: debug-launchpad
Requires: dbus

%description
Description: SDB daemon.

%prep
%setup -q

%build
%if "%{?tizen_profile_name}" == "wearable"
make %{?jobs:-j%jobs} wearable
%else
make %{?jobs:-j%jobs}
%endif

%install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%make_install
mkdir -p %{buildroot}%{_libdir}/systemd/system
%ifarch %{ix86}
install -m 0644 %SOURCE1002 %{buildroot}%{_libdir}/systemd/system/sdbd.service
mkdir -p %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants
ln -s %{_libdir}/systemd/system/sdbd.service %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants/
%else
install -m 0644 %SOURCE1001 %{buildroot}%{_libdir}/systemd/system/sdbd.service
%endif

mkdir -p %{buildroot}%{_prefix}/sbin
install -m 755 script/sdk_launch %{buildroot}%{_prefix}/sbin/

mkdir -p %{buildroot}/usr/bin
install -m 755 script/profile_command %{buildroot}/usr/bin/

%post
chsmack -a sdbd::home /home/developer
chsmack -t /home/developer

%files
%manifest sdbd.manifest
%defattr(-,root,root,-)
%{_prefix}/sbin/sdbd
%{_prefix}/sbin/sdk_launch
%{_libdir}/systemd/system/sdbd.service
%ifarch %{ix86}
%{_libdir}/systemd/system/emulator.target.wants/sdbd.service
%endif
/usr/share/license/%{name}
/usr/bin/profile_command

%changelog
* Mon Apr 21 2015 - Shingil Kang <shingil.kang@samsung.com>
- Execute debug-launchpad when zone is started

* Mon Apr 18 2015 - Shingil Kang <shingil.kang@samsung.com>
- Change "sdb forward" command to be zone-aware