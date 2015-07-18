/**
 * Created by c0untd0wn on 7/17/15.
 */

import static org.junit.Assert.assertEquals;
import org.junit.Test;

// A crude test based on JUnit
public class NaverAuthTest {
    @Test
    public void signInTest() {
        String id = "YOUR_NAVER_ID";
        String password = "YOUR_NAVER_PASSWORD";

        NaverAuth auth = NaverAuth.getInstance();
        assertEquals(NaverAuth.LOGIN_SUCCESS, auth.signIn(id, password));
    }
}
