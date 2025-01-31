# Mithras

Mithras is a cutting-edge simulation framework designed for full emulation and testing of IoT device firmware. It extends beyond existing solutions like Firmadyne and FirmAE by enabling seamless communication with external clients, such as companion apps installed on smartphones, making it suitable for real-time security assessments.

Features
- **Firmware Emulation**: Full emulation of IoT device firmware, allowing you to simulate and execute device-specific firmware in a controlled environment.
- **Static and Dynamic Instrumentation**: Offers both static instrumentation of firmware code and dynamic instrumentation of mobile companion apps to gather detailed execution data.
- **Mobile Companion App Support**: Enables communication between the emulated IoT firmware and the companion app, providing a fully integrated testing environment.
- **Real-Time Tracing**: Supports real-time tracing of PHP script executions, useful for analyzing how the firmware interacts with backend services or other devices.
- **Security Testing Ready**: Built to facilitate security testing of IoT firmware, enabling thorough vulnerability analysis and penetration testing.Mithras is a valuable asset for developers and researchers focused on IoT security, providing the tools necessary to test, instrument, and analyze IoT firmware and its associated mobile applications in real time.

<p align="center">
  <img src="./res/IoT Emulation - Run-Time Workflow.png" alt="drawing" width="400"/>
</p>

## Execution Environment

Mithras is designed to run on a PC with Ubuntu, and we recommend avoiding the use of virtual machines or Docker containers. This is due to limitations in the Firmadyne library, which Mithras relies on, as it may encounter issues when emulating certain IoT device firmware within virtualized environments.

Recommended Setup:
- **Operating System**: Ubuntu 22.10
- **Processor**: Intel 9th Gen i9 or equivalent
- **Memory**: 32 GB RAM

Mithras has been tested and optimized on the above hardware setup to ensure stable performance during firmware emulation and testing.

## Set Up Android Emulator

### 1. Download and Install Android Studio
You can download Android Studio from the official website:  
[Download Android Studio](https://developer.android.com/studio?hl=en)  
Follow the instructions provided for your operating system to complete the installation.

### 2. Setting up Environemnt Variables
```bash
echo "export ANDROID_HOME=~/Android/Sdk" | ~/.bashrc
```

### 3. Download and Configure Android Emulator
When setting up the Android emulator, ensure you select the **Google APIs** version instead of the **Google Play** version. We recommend installing the Android 11 emulator, as it is the most stablen and fully supports ARM translations. The Google APIs emulator grants root permissions, which are crucial for Mithras to interact with the companion app during testing.

Additionally, we recommend configuring an x86_64 Android emulator, as the modified mobile companion app used to test Mithras' main functionalities only supports the x86_64 architecture.

## Install Mithras

### 1. Prepare the Python Environment

**Install the Python Virtual Environment Package**  
To manage dependencies effectively, install the `python3-venv` package:
```bash
sudo apt install python3-venv
```

**Create a Virtual Environment**  
Use the venv Python module to create an isolated Python environment:
```bash
python3 -m venv venv
```

**Activate the Virtual Environment**  
Before installing dependencies, activate the virtual environment:
```bash
source venv/bin/activate
```

**Install `wheel`**:  
Ensure that the wheel package is installed to handle precompiled binaries:
```bash
pip install wheel
```

**Install Required Packages**  
Finally, install all the dependencies listed in the `requirements.txt` file:
```bash
pip install -r requirements.txt
```

### 2. Prepare the PHP Environment

**Install PHP (CLI Version)**  
Install PHP for running scripts from the command line.
```bash
sudo apt install php-cli
```

**Install Composer**  
Install Composer for managing PHP dependencies.
```bash
sudo apt install composer
```

**Install the Php-Parser Library**  
Install the Php-Parser library required for the project.
```bash
cd ./mithras/src/firmware-instrumenter
composer dump-autoload
composer require nikic/php-parser:^4.0
```

### 4. Setup Firmware-Analysis-Toolkit

**Install Binwalk**  
Required for firmware extraction and analysis.
```bash
sudo apt install binwalk
```

**Setup Firmware-Analysis-Toolkit**  
Navigate to the toolkit directory, copy the modified setup script, and run it.
```bash
cd firmware-analysis-toolkit
cp ../mithras/src/firmware-instrumenter/fat_setup.sh ./setup.sh
./setup.sh
```

**Update root password in fat.conf file**
Add the current system root password in the `sudo_password` field

### 4. Setup FirmAE

**Install Binwalk**  
Required for firmware extraction and analysis.
```bash
sudo apt install binwalk
```

**Setup Firmware-Analysis-Toolkit**  
Navigate to the toolkit directory, copy the modified setup script, and run it.
```bash
cd FirmAE
./download.sh
./install.sh
./init.sh
```

## Instrument IoT Device's Firmware

### 1. Download Firmware for Testing

Download a publicly available firmware file to be instrumented and emulated. The repository also contains a compatible companion app that can be used to communicate with this IoT device.
```bash
wget https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip
```

### 2. Prepare Emulation Environment
We highly recommend to use the FirmAE emulation engine since it is the most stable and supports a broader range od different firmwares compared to firmware-analysis-toolkit

**Firmware Emulation with Firmware-Analysis-Toolkit**  
Navigate to the Firmware Analysis Toolkit directory and start the firmware emulation.
```bash
cd ./firmware-analysis-toolkit
sudo ./fat.py <firmware-file>
```

**Firmware Emulation with Firmware-Analysis-Toolkit**  
Navigate to the FirmAE directory and start the firmware emulation.
```bash
cd ./FirmAE
sudo ./run.sh -r dlink <firmware-file>
```

### 3. Firmware Static Instrumentation

**Set Up Instrumentation Configurations**  
Modify the configuration file `./mithras/src/firmware-instrumenter/instrumentation_pipeline.json` with the necessary details for firmware instrumentation.
```json
{
    "firmware_name": "<name-of-the-firmware-to-emulate>",
    "root_password": "<system-root-password>"
}
```

**Instrument IoT Device Firmware**  
Activate the Python virtual environment and run the instrumentation pipeline.
```bash
source ./venv/bin/activate
cd ./mithras/src/firmware-instrumenter
python router_instrumenter_pipeline.py
```

### 4. Unpack Resources

**Unpack Frida-Server**  
Extract the Frida server binary:
```bash
unzip ./mithras/bin/frida-server.zip
```

**Unpack Companion App APK**  
Extract the companion app APK file:
```bash
unzip ./apps/companion_app.zip
```

### 5. Execute Mobile-IoT Emulated Environment

**Set Up Router Configurations**  
Modify the configuration file `./mithras/router_mapping.json`. This configuration files contains a list of firmware details. For each firmware, you have to provide a `name` (the same name passed to the firmware's instrumentation step) and its public `ip_address`
```json
{
  "firmware1": {"model": "firmware1_name", "ip_address": "firmware_1_ip_address"},
  "firmware2": {"model": "firmware2_name", "ip_address": "firmware_2_ip_address"},
  ...
}
```

### 6. Set Up Emulation Configurations

Modify the configuration files `./mithras/config.json` and `./mithras/router_mapping.json`. These files contain the running configurations that allow Mithras to establish the emulated Mobile-IoT ecosystem. Below are the key options you may need to modify:

- **firmware_name**: The same name used during the firmware instrumentation step. Ensure consistency with the firmware's setup.
- **android_sdk_platforms**: Defines the path of the `platforms` folder inside the Android SDK installed on the host machine.
- **proc_name**: The package name of the mobile companion app.
- **device_id**: The Android emulator's identifier, used by the `adb` tool to select the proper emulator when multiple instances are running.
- **device_name**: The Android emulator's name. This should be the same name you gave to the emulator during its creation.

### 7. Emulate Mobile-IoT Environment

**Emulate Instrumented Firmware**  
Navigate to the firmware directory and run the emulated firmware:
```bash
cd ./firmware-analysis-toolkit/firmadyne/scratch/<image-id>
./run.sh
```

**Run Mithras**  
Activate the virtual environment and run the firmware test script:
```bash
source venv/bin/activate
cd ./mithras
export ANDROID_HOME="<path-to-Android-Sdk-Folder>"
python test_firmware.py --firmware_name <firmware-name-in-router-mapping-json> --cf ./config.json
```
