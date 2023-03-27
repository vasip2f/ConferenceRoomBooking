import React, { useEffect, useState } from 'react';
import axios from 'axios';
// import { refereshToken } from '../../../Backend/controller/user-controller';
axios.defaults.withCredentials = true;
let firstRender = true;

const Welcome = () => {
  const [user, setUser] = useState();

  const refereshToken = async () => {
    const res = await axios.get("http://localhost:5000/api/referesh", {
      withCredentials: true,
    }).catch(err => console.log(err))

    const data = await res.data;
    return data;
  }

  const sendRequest = async () => {
    const res = await axios.get('http://localhost:5000/api/user', {
      withCredentials: true
    }).catch(err => console.log(err));
    const data = await res.data;
    return data;
  };
  useEffect(() => {
    if (firstRender) {
      firstRender = false
      sendRequest().then((data) => setUser(data.user))
    }

    let interval = setInterval(() => {
      refereshToken().then(data => setUser(data.user))
    }, 1000 * 29)


    return () => clearInterval(interval)
     


  }, []);


  return (
    <div>
      <center>
      <div><h1>Welcome..!</h1> <span>{user && <h3>{user.name}</h3>}</span> Please Select a Meeting Date</div>
      </center>
      
      
    </div>  
  )

};


export default Welcome