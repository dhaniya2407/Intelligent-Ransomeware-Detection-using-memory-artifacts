const handleLogin = async (e) => {
  e.preventDefault();

  try {
    const response = await fetch("http://127.0.0.1:8000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    const data = await response.json();

    console.log("Login Response:", data);

    if (response.ok) {
      localStorage.setItem("user", JSON.stringify(data));
      navigate("/dashboard");
    } else {
      alert(data.detail || "Invalid username or password");
    }
  } catch (error) {
    console.error("Login Error:", error);
    alert("Cannot connect to backend");
  }
};