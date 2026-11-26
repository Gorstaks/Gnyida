; Gnyida's own installer messages, English. Inno Setup's standard messages come from compiler:Default.isl.
; Every language folder has a file like this one with the same keys. %1 is filled in by setup; %n is a line break.
[CustomMessages]
AutoRotateGroup=Password rotator (optional)
AutoRotateTask=Keep this account's password secret, even from you. While you are signed in, Gnyida changes it to a random password every 10 minutes, so a stolen password stops working within minutes. When the PC starts, the password is cleared, so you sign in without one. Before you turn this on: passwords saved in your browser and in Windows may be lost, files you encrypted with Windows may become unreadable, after locking the screen you may need to restart the PC to get back in, and apps or scheduled tasks that use this password will stop working. Leave this off unless you are sure.
StatusStarting=Starting Gnyida...
ExploitShieldStartFailed=Setup couldn't turn on automatic exploit protection.
ExploitShieldScheduleFailed=Setup couldn't schedule automatic exploit protection. Details are in the ExploitShield audit log.
AutoRotateNotEnabled=Gnyida is installed, but the password rotator couldn't be turned on.%n%nDetails: %1
DotNetRequired=Gnyida needs .NET Framework 4.8.%n%nYes: open Microsoft's download page%nNo: cancel setup
DotNetRunAgain=After installing .NET Framework 4.8, run Gnyida setup again.
UpgradeStopFailed=Gnyida couldn't be stopped for the upgrade. Restart the PC and run setup again. If that doesn't help, please report the problem and include the setup log.
UpgradeExploitShieldStopFailed=Setup couldn't stop automatic exploit protection before the upgrade.
UpgradeExploitShieldScheduleFailed=Setup couldn't remove the old exploit protection schedule before the upgrade.
InstallDirNotProtected=Gnyida has to be installed under Program Files, because it runs with full system rights from its install folder. It is currently installed in %1, which is not protected. Uninstall it, then run setup again.
UninstallExploitShieldStopFailed=Gnyida ExploitShield couldn't be stopped, so the uninstall was cancelled.
UninstallExploitShieldScheduleFailed=The Gnyida ExploitShield schedule couldn't be removed, so the uninstall was cancelled.
AutoRotateUninstallBlankFailed=The uninstall was stopped so you don't get locked out. Gnyida couldn't clear this account's password, and removing the password rotator now could leave the account with a password nobody knows.%n%nDetails: %1%n%nFix the problem, then uninstall again.
AutoRotateUninstallExeMissing=The uninstall was stopped so you don't get locked out. The password rotator is still scheduled, but its program file is missing, so Gnyida can't clear this account's password. Install Gnyida again, then uninstall it.
