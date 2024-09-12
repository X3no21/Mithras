import subprocess

from appium.webdriver.common.appiumby import AppiumBy
from appium import webdriver
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import WebDriverWait
import os

from google_play_scraper import app


class PlaystoreLocators:
    PLAYSTORE_PACKAGE_NAME = 'com.android.vending'
    PLAYSTORE_MAIN_ACTIVITY = 'com.google.android.finsky.setupui.VpaSelectionOptionalStepActivity'

    def __init__(self, app_name):
        self.app_name = app_name
        self.SEARCH_BAR_BOX = (AppiumBy.XPATH, '//android.widget.TextView[contains(@text, "Search apps & '
                                               'games")]/../..')
        self.SEARCH_BAR_BOX_FOR = (AppiumBy.XPATH, '//android.widget.TextView[contains(@text, "Search for apps & '
                                                   'games")]/../..')
        self.SEARCH_BAR_BOX_TEXT_INPUT = (
            AppiumBy.XPATH, '//android.widget.TextView[contains(@text, "Search apps & '
                            'games")]/..')
        self.SEARCH_BAR_BOX_TEXT_INPUT_FOR = (
            AppiumBy.XPATH, '//android.widget.TextView[contains(@text, "Search for apps & '
                            'games")]/..')
        self.APP_ITEM_SEARCH_RESULT = (
            AppiumBy.XPATH, f'//android.view.View[contains(@content-desc, "{self.app_name}")]/..')
        self.APP_ITEM_SEARCH_RESULT_FRAME = (
            AppiumBy.XPATH, f'//android.widget.TextView[contains(@text, "{self.app_name}")]')
        self.INSTALL_BUTTON = (AppiumBy.XPATH, '//android.view.View[contains(@content-desc, "Install")]/..')
        self.OPEN_BUTTON = (AppiumBy.XPATH, '//android.view.View[contains(@content-desc, "Open")]/..[@enabled="true"]')
        self.PLAY_STORE_BUTTON = (
            AppiumBy.XPATH, '//android.widget.TextView[contains(@text, "Play Store")][@clickable="true"]')


class PlayStoreElements:

    def __init__(self, app_name):
        self.play_store_locator = PlaystoreLocators(app_name)

    def find_search_box_playstore(self, driver: webdriver.Remote):
        return WebDriverWait(driver=driver, timeout=80).until(
            ec.visibility_of_element_located(self.play_store_locator.SEARCH_BAR_BOX))

    def find_search_box_playstore_for(self, driver: webdriver.Remote):
        try:
            return WebDriverWait(driver=driver, timeout=5).until(
                ec.visibility_of_element_located(self.play_store_locator.SEARCH_BAR_BOX_FOR))
        except:
            return

    def find_search_box_text_input_for(self, driver: webdriver.Remote):
        try:
            return WebDriverWait(driver=driver, timeout=5).until(
                ec.presence_of_element_located(self.play_store_locator.SEARCH_BAR_BOX_TEXT_INPUT_FOR))
        except:
            return

    def find_search_box_text_input(self, driver: webdriver.Remote):
        return WebDriverWait(driver=driver, timeout=80).until(
            ec.presence_of_element_located(self.play_store_locator.SEARCH_BAR_BOX_TEXT_INPUT))

    def find_app_item_search_result(self, driver: webdriver.Remote):
        try:
            return WebDriverWait(driver=driver, timeout=5).until(
                ec.presence_of_element_located(self.play_store_locator.APP_ITEM_SEARCH_RESULT))
        except:
            return

    def find_app_item_search_result_frame(self, driver: webdriver.Remote):
        try:
            WebDriverWait(driver=driver, timeout=5).until(
                ec.presence_of_element_located(self.play_store_locator.APP_ITEM_SEARCH_RESULT_FRAME))

            return WebDriverWait(driver=driver, timeout=80).until(
                ec.presence_of_element_located(self.play_store_locator.INSTALL_BUTTON))
        except:
            return

    def find_install_button(self, driver: webdriver.Remote):
        return WebDriverWait(driver=driver, timeout=80).until(
            ec.presence_of_element_located(self.play_store_locator.INSTALL_BUTTON))

    def find_open_button(self, driver: webdriver.Remote):
        return WebDriverWait(driver=driver, timeout=1000).until(
            ec.presence_of_element_located(self.play_store_locator.OPEN_BUTTON))

    def find_play_store_button(self, driver: webdriver.Remote):
        return WebDriverWait(driver=driver, timeout=80).until(
            ec.presence_of_element_located(self.play_store_locator.PLAY_STORE_BUTTON))


class PlayStoreActions:

    def __init__(self, app_name):
        self.playstore_elem = PlayStoreElements(app_name)

    def tap_search_bar_play_store(self, driver: webdriver.Remote):
        self.playstore_elem.find_search_box_playstore(driver=driver).click()

    def tap_search_bar_play_store_for(self, driver: webdriver.Remote):
        view = self.playstore_elem.find_search_box_playstore_for(driver=driver)
        if view:
            view.click()
            return True
        return False

    def search_text_in_play_store_for(self, driver: webdriver.Remote, search_text: str):
        view = self.playstore_elem.find_search_box_text_input_for(driver=driver)
        if view:
            view.send_keys(search_text)
            driver.press_keycode(66)
            return True
        return False

    def search_text_in_play_store(self, driver: webdriver.Remote, search_text: str):
        self.playstore_elem.find_search_box_text_input(driver=driver).send_keys(search_text)
        driver.press_keycode(66)

    def tap_app_element_search_result(self, driver: webdriver.Remote):
        view = self.playstore_elem.find_app_item_search_result(driver=driver)
        if view:
            view.click()
            return True
        return False

    def tap_app_element_search_result_frame(self, driver: webdriver.Remote):
        view = self.playstore_elem.find_app_item_search_result_frame(driver=driver)
        if view:
            view.click()
            return True
        else:
            return False

    def tap_install_button(self, driver: webdriver.Remote):
        self.playstore_elem.find_install_button(driver=driver).click()

    def wait_open_button(self, driver: webdriver.Remote):
        self.playstore_elem.find_open_button(driver=driver)

    def tap_open_play_store_button(self, driver: webdriver.Remote):
        self.playstore_elem.find_play_store_button(driver=driver).click()


def init_appium_driver_without_app_package_name(udid, appium_port, get_platform_name, get_platform_version,
                                                get_device_name):
    desired_capabilities = {
        'platformName': get_platform_name,
        'platformVersion': get_platform_version,
        'udid': udid,
        'deviceName': get_device_name,
        'uiautomator2ServerInstallTimeout': 50000,
        'androidInstallTimeout': 30000,
        'adbExecTimeout': 30000,
        'newCommandTimeout': 90000
    }
    driver = webdriver.Remote(command_executor=f'http://127.0.0.1:{appium_port}/wd/hub',
                              desired_capabilities=desired_capabilities)
    return driver


def install_app(appium, app_pkg, apps_dir, udid, appium_port, get_platform_name, get_platform_version, get_device_name):
    app_details = app(app_pkg, country='it')
    app_name = app_details['title']
    search_text = f"pname:{app_pkg}"

    play_store_actions = PlayStoreActions(app_name)

    subprocess.call(["adb", "-s", udid, "shell", "am", "force-stop", "com.android.vending"])
    appium.restart_appium()

    driver = init_appium_driver_without_app_package_name(udid, appium_port, get_platform_name, get_platform_version,
                                                         get_device_name)
    # Press Home button
    driver.press_keycode(3)
    app_found = True
    play_store_actions.tap_open_play_store_button(driver=driver)
    search_bar_clicked = play_store_actions.tap_search_bar_play_store_for(driver=driver)
    if not search_bar_clicked:
        play_store_actions.tap_search_bar_play_store(driver=driver)
    search_bar_input = play_store_actions.search_text_in_play_store_for(driver=driver, search_text=search_text)
    if not search_bar_input:
        play_store_actions.search_text_in_play_store(driver=driver, search_text=search_text)
    install_button_clicked = play_store_actions.tap_app_element_search_result_frame(driver=driver)

    if not install_button_clicked:
        app_found = play_store_actions.tap_app_element_search_result(driver=driver)
        if app_found:
            play_store_actions.tap_install_button(driver=driver)
            play_store_actions.wait_open_button(driver=driver)
        else:
            subprocess.call(["adb", "-s", udid, "install", apps_dir + os.sep + app_pkg + ".apk"])
    else:
        play_store_actions.wait_open_button(driver=driver)

    driver.quit()
    appium.terminate()
    return app_found
