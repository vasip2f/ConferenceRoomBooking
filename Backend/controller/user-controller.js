const User = require('../model/User');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET_KEY = "mykey";

const signup = async (req, res, next) => {
    const { name, email, password } = req.body;
    let existingUser;
    try {
        existingUser = await User.findOne({ email: email });
    } catch (err) {
        console.log(err);
    }
    if (existingUser) {
        return res.status(400).json({ message: "User already exist! Login instead" })
    }
    const hashedpassword = bcrypt.hashSync(password);
    const user = new User({
        name,
        email,
        password: hashedpassword,
    });
    try {
        await user.save();
    } catch (err) {
        console.log(err);
    }
    return res.status(201).json({ message: user });
};

const login = async (req, res, next) => {
    const { email, password } = req.body;
    let existingUser;
    try {
        existingUser = await User.findOne({ email: email });
    } catch (err) {
        return new Error(err);
    }

    if (!existingUser) {
        return res.status(400).json({ message: "User not found! please signup" })
    }

    const ispasswordCorrect = bcrypt.compareSync(password, existingUser.password);
    if (!ispasswordCorrect) {
        return res.status(400).json({ message: "invalid email/password" })
    }

    const token = jwt.sign({ id: existingUser._id }, JWT_SECRET_KEY, {
        expiresIn: "2d"
    });

    console.log("Generated Token\n", token);

    if (req.cookies[`${existingUser._id}`]) {
        req.cookies[`${existingUser._id}`] = ""
    }

    res.cookie(String(existingUser._id), token, {
        path: '/',
        expires: new Date(Date.now() + 1000 * 30),
        httpOnly: true,
        sameSite: "lax"
    });
    return res.status(200).json({ message: "successfully logged In", user: existingUser, token });
};

const verifyToken = (req, res, next) => {

    const cookies = req.headers.cookie;
    const token = cookies.split("=")[1]
    console.log(token);
    // const headers = req.headers[`authorization`];
    // const token = headers.split(" ")[1];
    if (!token) {
        res.status(400).json({ message: "Token not fount!" })
    }

    jwt.verify(String(token), JWT_SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(400).json({ message: "Invalid Token!" })
        }
        console.log(user.id);
        req.id = user.id;
    });
    next();
};

const getuser = async (req, res, next) => {
    const userId = req.id;
    let user;
    try {
        user = await User.findById(userId, "-password");
    } catch (err) {
        return new Error(err)
    }

    if (!user) {
        return res.status(404).json({ message: "User not Found!!" })
    }
    return res.status(200).json({ user })
};
const refereshToken = (req, res, next) => {
    const cookies = req.headers.cookie;
    const prevToken = cookies.split("=")[1];
    if (!prevToken) {
        return res.status(400).json({ message: "could't find token" })
    }
    jwt.verify(String(prevToken), JWT_SECRET_KEY, (err, user) => {
        if (err) {
            console.log(err);
            return res.status(403).json({ message: "Authentication failed" })
        }
        res.clearCookie(`${user.id}`);
        req.cookies[`${user.id}`] = "";

        const token = jwt.sign({ id: user.id }, JWT_SECRET_KEY, {
            expiresIn: "2d",
        })

        console.log("Regenarated Token\n", token);

        res.cookie(String(user.id), token, {
            path: '/',
            expires: new Date(Date.now() + 1000 * 30),
            httpOnly: true,
            sameSite: "lax"
        });

        req.id = user.id;
        next();
    });

};

// const logout =(req, res, next)=>{
//     const cookies = req.headers.cookie;
//     const prevToken = cookies.split("=")[1];
//     if(!prevToken){
//         return res.status(400).json({message: "could't find token"})
//     }
//     jwt.verify(String(prevToken), JWT_SECRET_KEY,(err, user)=>{
//         if(err){
//             console.log(err);
//             return res.status(403).json({message: "Authentication failed"})
//         }
//         res.clearCookie(`${user.id}`);
//         req.cookies[`${user.id}`]= "";
//         return res.status(200).json({message: "Successfully Logged Out"})


//     })

// }


const logout = (req, res, next) => {
    const cookies = req.headers.cookie;
    const prevToken = cookies.split("=")[1];
    if (!prevToken) {
        return res.status(400).json({ message: "could't find token" })
    }

    jwt.verify(String(prevToken), JWT_SECRET_KEY, (err, user) => {
        if (err) {
            console.log(err);
            return res.status(403).json({ message: "Authentication failed" })
        }
        res.clearCookie(`${user.id}`);
        req.cookies[`${user.id}`] = "";
        return res.status(200).json({ message: "successfully logged out" })

    });
}

exports.signup = signup;
exports.login = login;
exports.verifyToken = verifyToken;
exports.getuser = getuser;
exports.refereshToken = refereshToken;
exports.logout = logout;