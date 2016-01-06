%bcond_with emulator

Name:       sdbd
Summary:    SDB daemon
Version:    3.0.2
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
BuildRequires:  pkgconfig(libtzplatform-config)
#BuildRequires: sec-product-features
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(capi-system-info)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(dbus-1)
BuildRequires: pkgconfig(dbus-glib-1)
Requires(post): libprivilege-control
Requires: sys-assert
Requires: dbus

%description
Description: SDB daemon.


%prep
%setup -q
cp %{SOURCE1003} .

%build
%if "%{?tizen_profile_name}" == "wearable"
%define wearable_profile on
%else
%define wearable_profile off
%endif
%ifarch %{ix86}
%define target_arch x86
%else
%define target_arch arm
%endif
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DWEARABLE_PROFILE=%{wearable_profile} \
	-DTARGET_ARCH=%{target_arch}

make %{?jobs:-j%jobs}

%install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%make_install
mkdir -p %{buildroot}%{_libdir}/systemd/system
mkdir -p %{buildroot}%{_unitdir}
%ifarch %{ix86}
install -m 0644 %SOURCE1002 %{buildroot}%{_libdir}/systemd/system/sdbd.service
mkdir -p %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants
ln -s %{_libdir}/systemd/system/sdbd.service %{buildroot}/%{_libdir}/systemd/system/emulator.target.wants/
%else
install -m 0644 %SOURCE1001 %{buildroot}%{_unitdir}/sdbd.service
install -m 0644 %SOURCE1004 %{buildroot}%{_unitdir}/sdbd_tcp.service
mkdir -p %{buildroot}/%{_libdir}/systemd/system/multi-user.target.wants
ln -s %{_libdir}/systemd/system/sdbd.service %{buildroot}/%{_libdir}/systemd/system/multi-user.target.wants/
%endif

mkdir -p %{buildroot}%{_prefix}/sbin
install -m 755 script/sdk_launch %{buildroot}%{_prefix}/sbin/

mkdir -p %{buildroot}/usr/bin
install -m 755 script/profile_command %{buildroot}/usr/bin/

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
%ifarch %{ix86}
%{_libdir}/systemd/system/emulator.target.wants/sdbd.service
%else
%{_unitdir}/sdbd_tcp.service
%{_libdir}/systemd/system/multi-user.target.wants/sdbd.service
%endif
/usr/share/license/%{name}
/usr/bin/profile_command

%changelog
