use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyLong, PyString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claim(serde_json::Value);

impl FromPyObject<'_> for Claim {
    fn extract(ob: &PyAny) -> PyResult<Self> {
        let value = extract_value(ob)?;
        Ok(Claim(value))
    }
}

/// Converts a Python object to a serde_json::Value.
fn extract_value(value: &PyAny) -> PyResult<serde_json::Value> {
    if let Ok(dict) = value.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict {
            let key: String = key.extract()?;
            let value = extract_value(value)?;
            map.insert(key, value);
        }
        Ok(serde_json::Value::Object(map))
    // Need to check bool before int otherwise it will mapped to (0, 1)
    } else if let Ok(val) = value.downcast::<PyBool>() {
        let rval = val.extract::<bool>()?;
        Ok(serde_json::Value::Bool(rval))
    } else if let Ok(val) = value.downcast::<PyString>() {
        Ok(serde_json::Value::String(val.to_string()))
    } else if let Ok(val) = value.downcast::<PyLong>() {
        let rval = val.extract::<i64>()?;
        Ok(serde_json::Value::Number(serde_json::Number::from(rval)))
    } else if let Ok(val) = value.downcast::<PyFloat>() {
        let rval = val.extract::<f64>()?;
        Ok(serde_json::Value::Number(
            serde_json::Number::from_f64(rval).unwrap(),
        ))
    } else if let Ok(val) = value.downcast::<PyList>() {
        let rval = val.extract::<Vec<&PyAny>>()?;
        let vec: Result<Vec<serde_json::Value>, _> = rval.into_iter().map(extract_value).collect();
        Ok(serde_json::Value::Array(vec?))
    } else if value.is_none() {
        Ok(serde_json::Value::Null)
    } else {
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Invalid value type",
        ))
    }
}

impl ToPyObject for Claim {
    fn to_object(&self, py: Python) -> PyObject {
        match &self.0 {
            serde_json::Value::Null => py.None(),
            serde_json::Value::Bool(b) => PyBool::new(py, *b).to_object(py),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i.to_object(py)
                } else if let Some(f) = n.as_f64() {
                    PyFloat::new(py, f).to_object(py)
                } else {
                    panic!("Failed to convert number to i64 or f64")
                }
            }
            serde_json::Value::String(s) => PyString::new(py, s).to_object(py),
            serde_json::Value::Array(arr) => {
                let pylist = PyList::empty(py);
                for item in arr {
                    pylist.append(Claim(item.clone()).to_object(py)).unwrap();
                }
                pylist.to_object(py)
            }
            serde_json::Value::Object(obj) => {
                let dict = PyDict::new(py);
                for (k, v) in obj {
                    dict.set_item(k, Claim(v.clone()).to_object(py)).unwrap();
                }
                dict.to_object(py)
            }
        }
    }
}

impl IntoPy<PyObject> for Claim {
    fn into_py(self, py: Python<'_>) -> PyObject {
        match &self.0 {
            serde_json::Value::Null => py.None(),
            serde_json::Value::Bool(b) => PyBool::new(py, *b).to_object(py),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i.to_object(py)
                } else if let Some(f) = n.as_f64() {
                    PyFloat::new(py, f).to_object(py)
                } else {
                    panic!("Failed to convert number to i64 or f64")
                }
            }
            serde_json::Value::String(s) => PyString::new(py, s).to_object(py),
            serde_json::Value::Array(arr) => {
                let pylist = PyList::empty(py);
                for item in arr {
                    pylist.append(Claim(item.clone()).to_object(py)).unwrap();
                }
                pylist.to_object(py)
            }
            serde_json::Value::Object(obj) => {
                let dict = PyDict::new(py);
                for (k, v) in obj {
                    dict.set_item(k, Claim(v.clone()).to_object(py)).unwrap();
                }
                dict.to_object(py)
            }
        }
    }
}
