import React, { useEffect,useState } from 'react';

import Typography from '@mui/material/Typography';
import { Navigate } from 'react-router-dom';


const Forbidden = (props) => {
    const [time,setTime]=useState(3);

    useEffect(()=>{
        const timer = setTimeout(()=>setTime(prev=>prev-1), 1000)
        return()=>{
            clearTimeout(timer)
        }
    },[time])

    return (
        <div style={{ textAlign: 'center', paddingTop: '50vh' }}>
            <Typography variant="h4">Access Forbidden</Typography>
            <Typography variant="subtitle1">{"Redirecting in "+time+" seconds."}</Typography>
            {time===0&&<Navigate to={"/"} />}
           
        </div>
    )
}

export default Forbidden;
