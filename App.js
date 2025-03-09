import React, { useEffect, useState } from "react";
import API from "./api";

function App() {
    const [message, setMessage] = useState("");

    useEffect(() => {
        API.get("/").then((res) => setMessage(res.data));
    }, []);

    return <h1>{message}</h1>;
}

export default App;