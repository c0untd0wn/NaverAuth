# NaverAuth
A Java library for signing in to Naver

## Usage
```java
String id = "YOUR_NAVER_ID";
String password = "YOUR_NAVER_PASSWORD";

CookieManager cookieManager;

NaverAuth auth = NaverAuth.getInstance();
int responseCode = auth.signIn(id, password);
if(responseCode == NaverAuth.LOGIN_SUCCESS) {
    cookieManager = auth.getCookieManager;
    CookieHandler.setDefault(cookieManager);
} else if(responseCode == NaverAuth.CONNECTION_ERROR) {
    // Check network status
} else if(responseCode == NaverAuth.WRONG_ID_OR_PASSWORD) {
    // Check your ID or PASSWORD
}

// Now access Naver with the cookies you've got
```

## TODO
- Write comments
- Code refactoring
- Migrate to Gradle
- Release JAR

## Acknowledgment
Developed with the help of ['네이버 자동 로그인 구현'](http://blog.drunkhacker.me/?p=457) written by [drunkhacker](https://github.com/drunkhacker)