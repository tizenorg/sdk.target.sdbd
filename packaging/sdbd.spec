#sbs-git:slp/pkgs/s/sdbd sdbd 0.0.1 aa7a3c179bce0053087116ae9ee35e8eb88ae5bd
Name:       sdbd
Summary:    SDB daemon
Version: 0.0.1
Release:    0
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz

%description
Description: SDB daemon


%prep
%setup -q

%build
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_sysconfdir}/init.d/sdbd

%ifarch %{ix86}
%{_sysconfdir}/rc.d/rc3.d/S40sdbd
%endif

