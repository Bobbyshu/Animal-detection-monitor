package book.manager.service.Impl;

import book.manager.entity.AuthUser;
import book.manager.mapper.UserMapper;
import book.manager.service.AuthService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

@Service
public class AuthServiceImpl implements AuthService {

    @Resource
    UserMapper mapper;

    @Override
    public void register(String name, String gender, String grade, String password) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        AuthUser user = new AuthUser(0, name, encoder.encode(password), "user");
        if (mapper.registerUser(user) <= 0) {
            throw new RuntimeException("failure for adding of user's basic information");
        }

        if (mapper.addStudentInfo(user.getId(), name, grade, gender) <= 0) {
            throw new RuntimeException("failure for inserting of student's basic information");
        }
    }

    public AuthUser findUser(HttpSession session) {
        AuthUser user = (AuthUser) session.getAttribute("user");
        if (user == null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            user = mapper.getPasswordByUsername(authentication.getName());
            session.setAttribute("user", user);
        }
        return user;
    }
}
