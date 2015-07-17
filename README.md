# NaverAuth
A Java library for signing in to Naver

## Usage
```java
String id = "YOUR_NAVER_ID";
String password = "YOUR_NAVER_password";
List<String> cookies;

NaverAuth auth = NaverAuth.getInstance();
if(auth.signIn(id, password) == NaverAuth.LOGIN_SUCCESS) {
    cookies = auth.getCookies();
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