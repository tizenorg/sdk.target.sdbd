Name:       sdbd
Summary:    SDB daemon
Version:    3.0.1
Release:    0
License:    Apache-2.0
Summary:    SDB daemon
Group:      System/Utilities
Source0:    %{name}-%{version}.tar.gz
Source1001:    sdbd_device.service
Source1002:    sdbd_emulator.service
Source1003:    %{name}.manifest
Source1004:    sdbd_tcp.service

BuildRequires: capi-system-info-devel >= 0.2.0
BuildRequires: cmake >= 2.8.3
Requires: dbus

%description
Description: SDB daemon.


%prep
%setup -q
cp %{SOURCE1003} .

%build
%cmake
make %{?jobs:-j%jobs}


%install
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system
%if 0%{?simulator}
install -m 0644 %SOURCE1002 %{buildroot}%{_libdir}/systemd/system/sdbd.service
mkdir -p %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants
ln -s %{_libdir}/systemd/system/sdbd.service %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants/
%else
install -m 0644 %SOURCE1001 %{buildroot}%{_libdir}/systemd/system/sdbd.service
install -m 0644 %SOURCE1004 %{buildroot}%{_libdir}/systemd/system/sdbd_tcp.service
%endif

mkdir -p %{buildroot}%{_prefix}/sbin
install -m 755 script/sdk_launch %{buildroot}%{_prefix}/sbin/

%files
%manifest sdbd.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_prefix}/sbin/sdbd
%{_prefix}/sbin/sdk_launch
%{_sysconfdir}/init.d/sdbd
%{_libdir}/systemd/system/sdbd.service
%if 0%{?simulator}
%{_libdir}/systemd/system/emulator.target.wants/sdbd.service
%else
%{_libdir}/systemd/system/sdbd_tcp.service
%endif

%changelog
