# Android JKS 证书生成工具

一个用于生成 Android APK 签名证书（JKS 格式）的 Go 程序。

## 功能特性

- 生成 JKS 格式的 Android 签名证书
- 支持自定义证书信息（国家、省份、组织等）
- 支持自定义 Keystore 路径、密码和别名
- 自动计算并显示证书指纹（MD5、SHA1、SHA256）
- 自动生成带时间戳的证书文件，避免覆盖
- 自动生成证书信息文件，保存所有证书详情
- 可通过配置文件自定义所有参数

## 使用方法

### 1. 配置证书信息

编辑 `build/config.json` 文件，自定义证书信息：

```json
{
  "keystore": {
    "filePath": "build/my-release-key.jks",
    "password": "123456",
    "keyAlias": "my-key",
    "keyPass": "123456"
  },
  "ca": {
    "country": "CN",
    "province": "Beijing",
    "organization": "MyCompany",
    "organizationalUnit": "Development",
    "commonName": "MyAndroidApp",
    "validityYears": 25
  }
}
```

**配置说明：**

- `keystore.filePath` - JKS 文件保存路径（基础路径，会自动添加时间戳）
- `keystore.password` - Keystore 密码
- `keystore.keyAlias` - Key 别名
- `keystore.keyPass` - Key 密码
- `ca.country` - 国家代码（如：CN、US）
- `ca.province` - 省份/州
- `ca.organization` - 组织名称
- `ca.organizationalUnit` - 组织单位
- `ca.commonName` - 通用名称（通常是应用名称）
- `ca.validityYears` - 证书有效期（年）

### 2. 运行程序

**方式一：直接运行 Go 源码**
```bash
go run main.go
```

**方式二：编译后运行**
```bash
go build -o android-jks-generator.exe main.go
./android-jks-generator.exe
```

### 3. 输出结果

程序会显示详细的证书信息，包括：

- Keystore 路径和密码信息
- 证书信息文件路径
- 证书序列号、主题、颁发者
- 证书有效期
- 证书指纹（MD5、SHA1、SHA256）

示例输出：

```
===================================================
APK签名证书生成成功！
===================================================

证书信息：
---------------------------------------------------
Keystore 路径: build/my-release-key-20260112-132539.jks
证书信息文件: build/my-release-key-20260112-132539.txt
Key Alias: chrelyonly
Keystore 密码: chrelyonly
Key 密码: chrelyonly

证书详情：
序列号: 1768195539127834800
主题: CN=chrelyonly CA,OU=chrelyonly,O=chrelyonly,ST=Yunnan,C=CN
颁发者: CN=chrelyonly CA,OU=chrelyonly,O=chrelyonly,ST=Yunnan,C=CN
有效期: 2026-01-12 05:25:39 至 2126-01-12 05:25:39

证书指纹：
MD5: ba89e572fb0c919911c900fea75909b9
SHA1: 10f9b69997c697a4c6d907ba150f0408a9ff3e31
SHA256: 4166039806deb4af7c9acc8ca4816252bd9e0b670fdc7a2008f650f2ad6b7677
===================================================
```

### 4. 输出文件

程序会自动生成带时间戳的文件，避免覆盖之前的证书：

- `build/my-release-key-20260112-132539.jks` - JKS 格式的签名证书
- `build/my-release-key-20260112-132539.txt` - 证书信息文件

**文件命名规则：**
- 时间戳格式：`YYYYMMDD-HHMMSS`
- 每次运行都会生成新的文件，不会覆盖之前的证书

### 5. 证书信息文件内容

生成的 `.txt` 文件包含完整的证书信息，方便查看和备份：

```
===================================================
APK签名证书信息
===================================================

证书信息：
---------------------------------------------------
Keystore 路径: build/my-release-key-20260112-132539.jks
Key Alias: chrelyonly
Keystore 密码: chrelyonly
Key 密码: chrelyonly

证书详情：
序列号: 1768195539127834800
主题: CN=chrelyonly CA,OU=chrelyonly,O=chrelyonly,ST=Yunnan,C=CN
颁发者: CN=chrelyonly CA,OU=chrelyonly,O=chrelyonly,ST=Yunnan,C=CN
有效期: 2026-01-12 05:25:39 至 2126-01-12 05:25:39

证书指纹：
MD5: ba89e572fb0c919911c900fea75909b9
SHA1: 10f9b69997c697a4c6d907ba150f0408a9ff3e31
SHA256: 4166039806deb4af7c9acc8ca4816252bd9e0b670fdc7a2008f650f2ad6b7677
===================================================
```

## 默认配置

如果 `config.json` 不存在或读取失败，程序会使用以下默认值：

**Keystore 配置：**
- **文件路径**: build/my-release-key.jks
- **密码**: 123456
- **Key Alias**: my-key
- **Key 密码**: 123456

**证书配置：**
- **国家**: CN
- **省份**: Beijing
- **组织**: MyCompany
- **组织单位**: Dev
- **通用名称**: MyApp
- **有效期**: 20 年

> **重要提示**: 生产环境中请务必修改这些默认密码！

## 在 Android 项目中使用

在 `build.gradle` 或 `build.gradle.kts` 中配置签名：

```gradle
android {
    signingConfigs {
        release {
            storeFile file("build/my-release-key-20260112-132539.jks")
            storePassword "chrelyonly"
            keyAlias "chrelyonly"
            keyPassword "chrelyonly"
        }
    }
    
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}
```

## 依赖

- Go 1.25+
- [keystore-go/v4](https://github.com/pavlo-v-chernykh/keystore-go) - JKS 文件处理库

## 许可证

MIT License