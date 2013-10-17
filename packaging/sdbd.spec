Name:       sdbd
Summary:    SDB daemon
Version:    2.2.13
Release:    0
License:    Apache-2.0
Summary:    SDB daemon
Group:      System/Utilities
Source0:    %{name}-%{version}.tar.gz
Source1001:    sdbd_device.service
Source1002:    sdbd_emulator.service

BuildRequires: capi-system-info-devel >= 0.2.0
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
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}

%make_install
mkdir -p %{buildroot}%{_libdir}/systemd/system
%if 0%{?simulator}
install -m 0644 %SOURCE1002 %{buildroot}%{_libdir}/systemd/system/sdbd.service
%else
install -m 0644 %SOURCE1001 %{buildroot}%{_libdir}/systemd/system/sdbd.service
%endif

mkdir -p %{buildroot}%{_prefix}/sbin
install -m 755 script/sdk_launch %{buildroot}%{_prefix}/sbin/

%post
chsmack -a sdbd::home /home/developer
chsmack -t /home/developer

%files
%manifest sdbd.manifest
%defattr(-,root,root,-)
%{_prefix}/sbin/sdbd
%{_prefix}/sbin/sdk_launch
%{_sysconfdir}/init.d/sdbd
%{_libdir}/systemd/system/sdbd.service

%changelog
