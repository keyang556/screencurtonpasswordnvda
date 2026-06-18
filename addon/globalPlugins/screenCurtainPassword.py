# A part of the Screen Curtain Password add-on for NVDA
# Copyright (C) 2026 chang
# This file is covered by the GNU General Public License, version 2 or later.

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import time
from collections.abc import Callable
from contextlib import contextmanager
from types import MethodType
from typing import Any

import addonHandler
import config
import core
import globalCommands
import globalPluginHandler
import gui
import screenCurtain
import ui
import wx
from gui import guiHelper, settingsDialogs
from gui.message import displayDialogAsModal
from gui.settingsDialogs import SettingsPanel
from logHandler import log
from scriptHandler import getLastScriptRepeatCount

addonHandler.initTranslation()


CONFIG_SECTION = "screenCurtainPassword"
PBKDF2_ITERATIONS = 260000
PASSWORD_RESET_CODE = "00000"
PASSWORD_RESET_DELAY_SECONDS = 5 * 60
_PASSWORD_RESET_REQUESTED_RESULT = 10001
_EM_SETPASSWORDCHAR = 0x00CC
_PASSWORD_MASK_CHAR = ord("*")

_CONFIG_SPEC = {
	"enabled": "boolean(default=false)",
	"passwordHash": 'string(default="")',
	"salt": 'string(default="")',
	"iterations": f"integer(default={PBKDF2_ITERATIONS})",
	"protectExit": "boolean(default=true)",
	"passwordResetRequestedAt": "float(default=0.0)",
}

_CONFIG_DEFAULTS = {
	"enabled": False,
	"passwordHash": "",
	"salt": "",
	"iterations": PBKDF2_ITERATIONS,
	"protectExit": True,
	"passwordResetRequestedAt": 0.0,
}

_bypassDepth = 0
_passwordResetTimer: Any | None = None


def _ensureConfig() -> dict[str, Any]:
	"""Register and return this add-on's config section."""
	if CONFIG_SECTION not in config.conf.spec:
		config.conf.spec[CONFIG_SECTION] = _CONFIG_SPEC
	try:
		section = config.conf[CONFIG_SECTION]
	except KeyError:
		config.conf[CONFIG_SECTION] = {}
		section = config.conf[CONFIG_SECTION]
	for key, defaultValue in _CONFIG_DEFAULTS.items():
		if key not in section:
			section[key] = defaultValue
	return section


def _passwordHash(password: str, salt: bytes, iterations: int) -> str:
	digest = hashlib.pbkdf2_hmac(
		"sha256",
		password.encode("utf-8"),
		salt,
		iterations,
	)
	return base64.b64encode(digest).decode("ascii")


def _saveConfig() -> None:
	try:
		config.conf.save()
	except Exception:
		log.error("Unable to save Screen Curtain password configuration.", exc_info=True)


def _stopPasswordResetTimer() -> None:
	global _passwordResetTimer
	if _passwordResetTimer is None:
		return
	try:
		_passwordResetTimer.Stop()
	except Exception:
		log.debugWarning("Unable to stop the Screen Curtain password reset timer.", exc_info=True)
	_passwordResetTimer = None


def _storedPasswordExists(section: dict[str, Any] | None = None) -> bool:
	section = section or _ensureConfig()
	return bool(section["passwordHash"] and section["salt"])


def _getPasswordResetRequestedAt(section: dict[str, Any]) -> float:
	try:
		return float(section["passwordResetRequestedAt"] or 0.0)
	except (TypeError, ValueError):
		log.debugWarning("Invalid Screen Curtain password reset timestamp.", exc_info=True)
		section["passwordResetRequestedAt"] = 0.0
		return 0.0


def _clearStoredPassword(*, save: bool = False, announce: bool = False) -> None:
	_stopPasswordResetTimer()
	section = _ensureConfig()
	section["passwordHash"] = ""
	section["salt"] = ""
	section["iterations"] = PBKDF2_ITERATIONS
	section["enabled"] = False
	section["passwordResetRequestedAt"] = 0.0
	if save:
		_saveConfig()
	if announce:
		ui.message(_("Screen Curtain password cleared. Password protection is disabled."))


def _completePasswordResetIfDue() -> bool:
	section = _ensureConfig()
	requestedAt = _getPasswordResetRequestedAt(section)
	if requestedAt <= 0:
		return False
	if not _storedPasswordExists(section):
		section["passwordResetRequestedAt"] = 0.0
		return False
	if time.time() - requestedAt < PASSWORD_RESET_DELAY_SECONDS:
		return False
	_clearStoredPassword(save=True, announce=True)
	return True


def _completeScheduledPasswordReset() -> None:
	global _passwordResetTimer
	_passwordResetTimer = None
	_ = _completePasswordResetIfDue()


def _schedulePasswordResetTimer(remainingSeconds: float) -> None:
	global _passwordResetTimer
	_stopPasswordResetTimer()
	delayMs = max(1, int(remainingSeconds * 1000))
	_passwordResetTimer = wx.CallLater(delayMs, _completeScheduledPasswordReset)


def _resumePendingPasswordReset() -> None:
	if _completePasswordResetIfDue():
		return
	section = _ensureConfig()
	requestedAt = _getPasswordResetRequestedAt(section)
	if requestedAt <= 0 or not _storedPasswordExists(section):
		return
	_schedulePasswordResetTimer(PASSWORD_RESET_DELAY_SECONDS - (time.time() - requestedAt))


def _cancelPasswordResetRequest(*, save: bool = False) -> None:
	_stopPasswordResetTimer()
	section = _ensureConfig()
	if _getPasswordResetRequestedAt(section) <= 0:
		return
	section["passwordResetRequestedAt"] = 0.0
	if save:
		_saveConfig()


def _requestPasswordReset() -> None:
	section = _ensureConfig()
	if not _storedPasswordExists(section):
		return
	requestedAt = _getPasswordResetRequestedAt(section)
	now = time.time()
	if requestedAt <= 0 or now - requestedAt >= PASSWORD_RESET_DELAY_SECONDS:
		section["passwordResetRequestedAt"] = now
		remainingSeconds = float(PASSWORD_RESET_DELAY_SECONDS)
		_saveConfig()
	else:
		remainingSeconds = PASSWORD_RESET_DELAY_SECONDS - (now - requestedAt)
	remainingMinutes = max(1, int((remainingSeconds + 59) // 60))
	_schedulePasswordResetTimer(remainingSeconds)
	ui.message(
		_(
			"Password reset requested. The stored Screen Curtain password will be cleared in {minutes} minutes.",
		).format(minutes=remainingMinutes),
	)


def _storePassword(password: str) -> None:
	_cancelPasswordResetRequest()
	section = _ensureConfig()
	salt = os.urandom(16)
	section["salt"] = base64.b64encode(salt).decode("ascii")
	section["iterations"] = PBKDF2_ITERATIONS
	section["passwordHash"] = _passwordHash(password, salt, PBKDF2_ITERATIONS)


def _hasStoredPassword() -> bool:
	_ = _completePasswordResetIfDue()
	return _storedPasswordExists()


def _verifyPassword(password: str) -> bool:
	section = _ensureConfig()
	if not _hasStoredPassword():
		return False
	try:
		salt = base64.b64decode(section["salt"])
		iterations = int(section["iterations"] or PBKDF2_ITERATIONS)
	except Exception:
		log.debugWarning("Invalid Screen Curtain password metadata.", exc_info=True)
		return False
	actualHash = _passwordHash(password, salt, iterations)
	return hmac.compare_digest(actualHash, section["passwordHash"])


def _isProtectionActive() -> bool:
	section = _ensureConfig()
	return bool(section["enabled"]) and _hasStoredPassword()


def _isScreenCurtainRunning() -> bool:
	controller = getattr(screenCurtain, "screenCurtain", None)
	return bool(controller and controller.enabled)


def _shouldProtectExit() -> bool:
	section = _ensureConfig()
	return _isProtectionActive() and bool(section["protectExit"]) and _isScreenCurtainRunning()


def _shouldProtectScreenCurtainDisable() -> bool:
	return _isProtectionActive() and _isScreenCurtainRunning()


@contextmanager
def _bypassPasswordGuard():
	global _bypassDepth
	_bypassDepth += 1
	try:
		yield
	finally:
		_bypassDepth -= 1


def _isPasswordGuardBypassed() -> bool:
	return _bypassDepth > 0


def _setPasswordCtrlVisible(passwordCtrl: wx.TextCtrl, visible: bool) -> None:
	"""Toggle a password TextCtrl without rebuilding the dialog layout."""
	try:
		ctypes.windll.user32.SendMessageW(
			passwordCtrl.GetHandle(),
			_EM_SETPASSWORDCHAR,
			0 if visible else _PASSWORD_MASK_CHAR,
			0,
		)
		passwordCtrl.Refresh()
	except Exception:
		log.debugWarning("Unable to toggle password visibility.", exc_info=True)


class _PasswordPromptDialog(wx.Dialog):
	def __init__(self, parent: wx.Window | None, actionLabel: str):
		super().__init__(parent, title=_("Screen Curtain password"))
		mainSizer = wx.BoxSizer(wx.VERTICAL)
		settingsSizer = wx.BoxSizer(wx.VERTICAL)
		sHelper = guiHelper.BoxSizerHelper(self, sizer=settingsSizer)

		sHelper.addItem(wx.StaticText(self, label=actionLabel))
		self._passwordCtrl = sHelper.addLabeledControl(
			_("&Password:"),
			wx.TextCtrl,
			style=wx.TE_PASSWORD | wx.TE_PROCESS_ENTER,
		)
		self._showPasswordCheckBox = sHelper.addItem(
			wx.CheckBox(self, label=_("Sho&w password")),
		)
		self._showPasswordCheckBox.Bind(wx.EVT_CHECKBOX, self._onShowPasswordChanged)
		self._passwordCtrl.Bind(wx.EVT_TEXT_ENTER, self._onOk)

		mainSizer.Add(settingsSizer, border=guiHelper.BORDER_FOR_DIALOGS, flag=wx.ALL | wx.EXPAND)
		mainSizer.Add(self.CreateSeparatedButtonSizer(wx.OK | wx.CANCEL), flag=wx.EXPAND | wx.ALL)
		self.SetSizer(mainSizer)
		mainSizer.Fit(self)
		self.CentreOnScreen()
		self.SetEscapeId(wx.ID_CANCEL)
		self.Bind(wx.EVT_BUTTON, self._onOk, id=wx.ID_OK)

	def _onShowPasswordChanged(self, evt: wx.CommandEvent) -> None:
		_setPasswordCtrlVisible(self._passwordCtrl, self._showPasswordCheckBox.IsChecked())

	def _onOk(self, evt: wx.CommandEvent) -> None:
		password = self._passwordCtrl.GetValue()
		if _verifyPassword(password):
			_cancelPasswordResetRequest(save=True)
			self.EndModal(wx.ID_OK)
			return
		if password == PASSWORD_RESET_CODE and _hasStoredPassword():
			_requestPasswordReset()
			self.EndModal(_PASSWORD_RESET_REQUESTED_RESULT)
			return
		wx.MessageBox(
			_("Incorrect password."),
			_("Screen Curtain password"),
			wx.OK | wx.ICON_ERROR,
			self,
		)
		self._passwordCtrl.SetValue("")
		self._passwordCtrl.SetFocus()


def _authenticate(actionLabel: str, parent: wx.Window | None = None) -> bool:
	if not _isProtectionActive():
		return True
	parent = parent or getattr(gui, "mainFrame", None)
	dialog = _PasswordPromptDialog(parent, actionLabel)
	try:
		return displayDialogAsModal(dialog) == wx.ID_OK
	finally:
		dialog.Destroy()


def _authenticateAsync(
	actionLabel: str,
	onSuccess: Callable[[], None],
	onFailure: Callable[[], None] | None = None,
	parent: wx.Window | None = None,
) -> None:
	if not _isProtectionActive():
		onSuccess()
		return
	parent = parent or getattr(gui, "mainFrame", None)
	dialog = _PasswordPromptDialog(parent, actionLabel)

	def onResult(result: int) -> None:
		if result == wx.ID_OK:
			onSuccess()
		elif result != _PASSWORD_RESET_REQUESTED_RESULT and onFailure is not None:
			onFailure()

	gui.runScriptModalDialog(dialog, onResult)


class ScreenCurtainPasswordSettingsPanel(SettingsPanel):
	# Translators: Settings category title for this add-on.
	title = _("Screen Curtain Password")

	def makeSettings(self, sizer: wx.BoxSizer) -> None:
		self._config = _ensureConfig()
		self._hadPassword = _hasStoredPassword()
		self._initialEnabled = bool(self._config["enabled"])
		self._initialProtectExit = bool(self._config["protectExit"])

		sHelper = guiHelper.BoxSizerHelper(self, sizer=sizer)
		self._enabledCheckBox = sHelper.addItem(
			wx.CheckBox(self, label=_("&Require a password before disabling Screen Curtain")),
		)
		self._enabledCheckBox.SetValue(self._initialEnabled)

		self._protectExitCheckBox = sHelper.addItem(
			wx.CheckBox(self, label=_("Protect NVDA e&xit or restart while Screen Curtain is active")),
		)
		self._protectExitCheckBox.SetValue(self._initialProtectExit)

		if self._hadPassword:
			self._currentPasswordCtrl = sHelper.addLabeledControl(
				_("Current password:"),
				wx.TextCtrl,
				style=wx.TE_PASSWORD,
			)
		else:
			self._currentPasswordCtrl = None

		self._newPasswordCtrl = sHelper.addLabeledControl(
			_("&New password:"),
			wx.TextCtrl,
			style=wx.TE_PASSWORD,
		)
		self._confirmPasswordCtrl = sHelper.addLabeledControl(
			_("&Confirm new password:"),
			wx.TextCtrl,
			style=wx.TE_PASSWORD,
		)
		self._showPasswordsCheckBox = sHelper.addItem(
			wx.CheckBox(self, label=_("Sho&w passwords")),
		)
		self._showPasswordsCheckBox.Bind(wx.EVT_CHECKBOX, self._onShowPasswordsChanged)

		if self._hadPassword:
			sHelper.addItem(
				wx.StaticText(
					self,
					label=_("Leave the new password fields blank to keep the current password."),
				),
			)

	def _passwordCtrls(self) -> tuple[wx.TextCtrl, ...]:
		ctrls = [self._newPasswordCtrl, self._confirmPasswordCtrl]
		if self._currentPasswordCtrl is not None:
			ctrls.insert(0, self._currentPasswordCtrl)
		return tuple(ctrls)

	def _onShowPasswordsChanged(self, evt: wx.CommandEvent) -> None:
		showPasswords = self._showPasswordsCheckBox.IsChecked()
		for ctrl in self._passwordCtrls():
			_setPasswordCtrlVisible(ctrl, showPasswords)

	def _requiresCurrentPassword(self) -> bool:
		if not self._hadPassword:
			return False
		return (
			self._enabledCheckBox.IsChecked() != self._initialEnabled
			or self._protectExitCheckBox.IsChecked() != self._initialProtectExit
			or bool(self._newPasswordCtrl.GetValue())
			or bool(self._confirmPasswordCtrl.GetValue())
		)

	def isValid(self) -> bool:
		newPassword = self._newPasswordCtrl.GetValue()
		confirmPassword = self._confirmPasswordCtrl.GetValue()
		if bool(newPassword) != bool(confirmPassword) or newPassword != confirmPassword:
			self._validationErrorMessageBox(
				_("The new password and confirmation do not match."),
				_("New password"),
			)
			self._newPasswordCtrl.SetFocus()
			return False
		if newPassword == PASSWORD_RESET_CODE:
			self._validationErrorMessageBox(
				_("The password 00000 is reserved for password reset. Choose a different password."),
				_("New password"),
			)
			self._newPasswordCtrl.SetFocus()
			return False
		if self._enabledCheckBox.IsChecked() and not self._hadPassword and not newPassword:
			self._validationErrorMessageBox(
				_("Set a password before enabling Screen Curtain password protection."),
				_("Require a password before disabling Screen Curtain"),
			)
			self._newPasswordCtrl.SetFocus()
			return False
		if self._requiresCurrentPassword():
			currentPassword = self._currentPasswordCtrl.GetValue() if self._currentPasswordCtrl else ""
			if not _verifyPassword(currentPassword):
				self._validationErrorMessageBox(
					_("Enter the current password to change Screen Curtain password settings."),
					_("Current password"),
				)
				if self._currentPasswordCtrl:
					self._currentPasswordCtrl.SetFocus()
				return False
			_cancelPasswordResetRequest()
		return super().isValid()

	def onSave(self) -> None:
		newPassword = self._newPasswordCtrl.GetValue()
		if newPassword:
			_storePassword(newPassword)
		self._config["enabled"] = self._enabledCheckBox.IsChecked()
		self._config["protectExit"] = self._protectExitCheckBox.IsChecked()


class GlobalPlugin(globalPluginHandler.GlobalPlugin):
	__gestures = {
		"kb:NVDA+control+escape": "toggleScreenCurtain",
	}

	def __init__(self, *args: Any, **kwargs: Any) -> None:
		super().__init__(*args, **kwargs)
		_ = _ensureConfig()
		self._originalTriggerNVDAExit: Callable[..., bool] | None = None
		self._guardedTriggerNVDAExit: Callable[..., bool] | None = None
		self._originalPrivacyEnsureState: Callable[..., None] | None = None
		self._guardedPrivacyEnsureState: Callable[..., None] | None = None
		self._screenCurtainController: Any | None = None
		self._originalScreenCurtainDisable: Callable[..., None] | None = None
		self._guardedScreenCurtainDisable: Callable[..., None] | None = None
		self._screenCurtainControllerHadOwnDisable = False
		self._registerSettingsPanel()
		_resumePendingPasswordReset()
		self._patchCoreExit()
		self._patchPrivacyPanel()
		self._patchScreenCurtainController()

	def terminate(self) -> None:
		self._restoreScreenCurtainController()
		self._restorePrivacyPanel()
		self._restoreCoreExit()
		_stopPasswordResetTimer()
		self._unregisterSettingsPanel()
		super().terminate()

	def _registerSettingsPanel(self) -> None:
		if ScreenCurtainPasswordSettingsPanel not in gui.NVDASettingsDialog.categoryClasses:
			gui.NVDASettingsDialog.categoryClasses.append(ScreenCurtainPasswordSettingsPanel)

	def _unregisterSettingsPanel(self) -> None:
		try:
			gui.NVDASettingsDialog.categoryClasses.remove(ScreenCurtainPasswordSettingsPanel)
		except ValueError:
			pass

	def _patchCoreExit(self) -> None:
		self._originalTriggerNVDAExit = core.triggerNVDAExit

		def guardedTriggerNVDAExit(*args: Any, **kwargs: Any) -> bool:
			if _shouldProtectExit() and not _authenticate(
				_("Enter the Screen Curtain password to exit or restart NVDA."),
			):
				ui.message(_("NVDA exit canceled."))
				return False
			with _bypassPasswordGuard():
				if self._originalTriggerNVDAExit is None:
					return False
				return self._originalTriggerNVDAExit(*args, **kwargs)

		self._guardedTriggerNVDAExit = guardedTriggerNVDAExit
		core.triggerNVDAExit = guardedTriggerNVDAExit

	def _restoreCoreExit(self) -> None:
		if self._guardedTriggerNVDAExit is not None and core.triggerNVDAExit is self._guardedTriggerNVDAExit:
			core.triggerNVDAExit = self._originalTriggerNVDAExit
		self._guardedTriggerNVDAExit = None
		self._originalTriggerNVDAExit = None

	def _patchPrivacyPanel(self) -> None:
		self._originalPrivacyEnsureState = (
			settingsDialogs.PrivacyAndSecuritySettingsPanel._ensureScreenCurtainEnableState
		)

		def guardedEnsureScreenCurtainEnableState(panel: Any, evt: Any) -> None:
			try:
				disablingScreenCurtain = (
					not evt.IsChecked()
					and getattr(screenCurtain, "screenCurtain", None) is not None
					and screenCurtain.screenCurtain.enabled
				)
			except Exception:
				disablingScreenCurtain = False
			if (
				disablingScreenCurtain
				and not _isPasswordGuardBypassed()
				and _shouldProtectScreenCurtainDisable()
				and not _authenticate(
					_("Enter the Screen Curtain password to disable Screen Curtain."), parent=panel
				)
			):
				panel._screenCurtainEnabledCheckbox.SetValue(True)
				ui.message(_("Screen Curtain remains enabled."))
				return
			with _bypassPasswordGuard():
				if self._originalPrivacyEnsureState is None:
					return None
				return self._originalPrivacyEnsureState(panel, evt)

		self._guardedPrivacyEnsureState = guardedEnsureScreenCurtainEnableState
		settingsDialogs.PrivacyAndSecuritySettingsPanel._ensureScreenCurtainEnableState = (
			guardedEnsureScreenCurtainEnableState
		)

	def _restorePrivacyPanel(self) -> None:
		currentMethod = settingsDialogs.PrivacyAndSecuritySettingsPanel._ensureScreenCurtainEnableState
		if self._guardedPrivacyEnsureState is not None and currentMethod is self._guardedPrivacyEnsureState:
			settingsDialogs.PrivacyAndSecuritySettingsPanel._ensureScreenCurtainEnableState = (
				self._originalPrivacyEnsureState
			)
		self._guardedPrivacyEnsureState = None
		self._originalPrivacyEnsureState = None

	def _patchScreenCurtainController(self) -> None:
		controller = getattr(screenCurtain, "screenCurtain", None)
		if controller is None or controller is self._screenCurtainController:
			return
		self._restoreScreenCurtainController()
		self._screenCurtainController = controller
		self._screenCurtainControllerHadOwnDisable = "disable" in getattr(controller, "__dict__", {})
		self._originalScreenCurtainDisable = controller.disable

		def guardedDisable(_controller: Any, *args: Any, **kwargs: Any) -> None:
			if (
				not _isPasswordGuardBypassed()
				and _shouldProtectScreenCurtainDisable()
				and not _authenticate(_("Enter the Screen Curtain password to disable Screen Curtain."))
			):
				ui.message(_("Screen Curtain remains enabled."))
				return None
			with _bypassPasswordGuard():
				if self._originalScreenCurtainDisable is None:
					return None
				return self._originalScreenCurtainDisable(*args, **kwargs)

		self._guardedScreenCurtainDisable = MethodType(guardedDisable, controller)
		controller.disable = self._guardedScreenCurtainDisable

	def _restoreScreenCurtainController(self) -> None:
		if (
			self._screenCurtainController is not None
			and self._guardedScreenCurtainDisable is not None
			and getattr(self._screenCurtainController, "disable", None) is self._guardedScreenCurtainDisable
		):
			if self._screenCurtainControllerHadOwnDisable:
				self._screenCurtainController.disable = self._originalScreenCurtainDisable
			else:
				try:
					del self._screenCurtainController.disable
				except AttributeError:
					self._screenCurtainController.disable = self._originalScreenCurtainDisable
		self._screenCurtainController = None
		self._originalScreenCurtainDisable = None
		self._guardedScreenCurtainDisable = None
		self._screenCurtainControllerHadOwnDisable = False

	def _disableScreenCurtainAfterAuthentication(self) -> None:
		controller = getattr(screenCurtain, "screenCurtain", None)
		if controller is None:
			ui.message(_("Screen curtain not available"))
			return
		message = _("Screen curtain disabled")
		try:
			with _bypassPasswordGuard():
				controller.disable()
		except Exception:
			log.error("Screen curtain termination error", exc_info=True)
			message = _("Could not disable screen curtain")
		finally:
			try:
				globalCommands.commands._toggleScreenCurtainMessage = message
			except Exception:
				log.debugWarning("Unable to cache Screen Curtain toggle message.", exc_info=True)
			ui.message(message)

	def script_toggleScreenCurtain(self, gesture: Any) -> None:
		self._patchScreenCurtainController()
		if _shouldProtectScreenCurtainDisable() and getLastScriptRepeatCount() == 0:
			_authenticateAsync(
				_("Enter the Screen Curtain password to disable Screen Curtain."),
				self._disableScreenCurtainAfterAuthentication,
				lambda: ui.message(_("Screen Curtain remains enabled.")),
			)
			return
		with _bypassPasswordGuard():
			globalCommands.commands.script_toggleScreenCurtain(gesture)

	script_toggleScreenCurtain.__doc__ = _(
		"Toggles Screen Curtain, asking for the Screen Curtain password before disabling it.",
	)
