import React from 'react'
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Box,Typography,TextField,Button } from '@mui/material';
import { useDispatch } from 'react-redux';
import { authActions } from '../store';

const Login = () => {
    const dispatch = useDispatch();
    const history = useNavigate();
    const [inputs, setInputs] = useState({
        email: "",
        password: "",
    });

    const handleChange = (e) => {
        setInputs((prev) => ({
            ...prev,
            [e.target.name]: e.target.value
        }));
        // console.log(e.target.name, "value", e.target.value)
    };

    const sendRequest = async () => {
        const res = await axios.post('http://localhost:5000/api/login', {
            email: inputs.email,
            password: inputs.password
        }).catch((err) => console.log(err));
        const data = await res.data;
        return data;
    };
    const handlesubmit = (e) => {
        e.preventDefault();
        // console.log(inputs);

        //Send Request

        sendRequest().then(()=>dispatch(authActions.login())).then(() => history("/user",));
    };
    return (
        <div>

            <form onSubmit={handlesubmit}>
                <Box marginLeft="auto" marginRight="auto" width={300}
                    display='flex' flexDirection={'column'}
                    justifyContent="center" alignItems="center" >
                    <Typography variant='h2'>LOGIN</Typography>
                    
                    <TextField
                        name='email'
                        onChange={handleChange}
                        type={'email'}
                        value={inputs.email}
                        variant='outlined'
                        placeholder='Your@gmail'
                        margin='normal' />
                    <TextField
                        name='password'
                        onChange={handleChange}
                        type={'password'}
                        value={inputs.password}
                        variant='outlined'
                        placeholder='Password'
                        margin='normal' />
                    <Button variant='contained' type='submit'>Let's Go</Button>
                </Box>
            </form>
        </div>
    )
};


export default Login