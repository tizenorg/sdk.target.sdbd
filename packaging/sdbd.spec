%bcond_with emulator

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
Source1005:    sdbd_tcp_only.service

BuildRequires: capi-system-info-devel >= 0.2.0
BuildRequires: cmake >= 2.8.3
BuildRequires:  pkgconfig(libtzplatform-config)
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

mkdir -p %{buildroot}%{_unitdir}
%if %{with emulator}
install -m 0644 %SOURCE1002 %{buildroot}%{_unitdir}/sdbd.service
mkdir -p %{buildroot}/%{_unitdir}/emulator.target.wants
ln -s %{_unitdir}/sdbd.service %{buildroot}/%{_unitdir}/emulator.target.wants/
%else
install -m 0644 %SOURCE1001 %{buildroot}%{_unitdir}/sdbd.service
install -m 0644 %SOURCE1004 %{buildroot}%{_unitdir}/sdbd_tcp.service
install -m 0644 %SOURCE1005 %{buildroot}%{_unitdir}/sdbd_tcp_only.service
%endif

mkdir -p %{buildroot}%{_prefix}/sbin
install -m 755 script/sdk_launch %{buildroot}%{_prefix}/sbin/


%post
. %{_sysconfdir}/tizen-platform.conf
if ! getent passwd "${TZ_SDK_USER_NAME}" > /dev/null; then
  rm -rf "${TZ_SDK_HOME}"
  useradd -u 5100 -s /bin/false -m -d "${TZ_SDK_HOME}" "${TZ_SDK_USER_NAME}"
  getent group developer > /dev/null || groupadd -g 5100 developer
  for x in app_logging crash developer; do
    usermod -A app_logging "${TZ_SDK_USER_NAME}"
  done
fi

%files
%manifest sdbd.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_prefix}/sbin/sdbd
%{_prefix}/sbin/sdk_launch
%attr(0755, root, root) %{_sysconfdir}/init.d/sdbd
%{_unitdir}/sdbd.service
%if %{with emulator}
%{_unitdir}/emulator.target.wants/sdbd.service
%else
%{_unitdir}/sdbd_tcp.service
%{_unitdir}/sdbd_tcp_only.service
%endif

%changelog
