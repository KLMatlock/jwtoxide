use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyLong, PyString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claim(serde_json::Value);

impl FromPyObject<'_> for Claim {
    fn extract_bound(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        let value = extract_value_bound(obj)?;
        Ok(Claim(value))
    }
}


/// Converts a Python object to a serde_json::Value.
fn extract_value_bound(value: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if let Ok(dict) = value.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict {
            let key: String = key.extract()?;
            let value = extract_value_bound(&value)?;
            map.insert(key, value);
        }
        return Ok(serde_json::Value::Object(map))
    } else if let Ok(val) = value.downcast::<PyBool>() {
        let rval = val.extract::<bool>()?;
        return Ok(serde_json::Value::Bool(rval))
    } else if let Ok(val) = value.downcast::<PyString>() {
        return Ok(serde_json::Value::String(val.to_string()))
    } else if let Ok(val) = value.downcast::<PyLong>() {
        let rval = val.extract::<i64>()?;
        return Ok(serde_json::Value::Number(serde_json::Number::from(rval)))
    } else if let Ok(val) = value.downcast::<PyFloat>() {
        let rval = val.extract::<f64>()?;
        return Ok(serde_json::Value::Number(
            serde_json::Number::from_f64(rval).unwrap(),
        ))
    } else if let Ok(val) = value.downcast::<PyList>() {
        let list_iter = |val| extract_value_bound(&val);
        let vec: Result<Vec<serde_json::Value>, _> = val.into_iter().map(list_iter).collect();
        return Ok(serde_json::Value::Array(vec?))
    } else if value.is_none() {
        return Ok(serde_json::Value::Null)
    }
    Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
        "Invalid value type",
    ))
}


impl ToPyObject for Claim {
    fn to_object(&self, py: Python) -> PyObject {
        match &self.0 {
            serde_json::Value::Null => py.None(),
            serde_json::Value::Bool(b) => PyBool::new_bound(py, *b).to_object(py),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i.to_object(py)
                } else if let Some(f) = n.as_f64() {
                    PyFloat::new_bound(py, f).to_object(py)
                } else {
                    panic!("Failed to convert number to i64 or f64")
                }
            }
            serde_json::Value::String(s) => PyString::new_bound(py, s).to_object(py),
            serde_json::Value::Array(arr) => {
                let pylist = PyList::empty_bound(py);
                for item in arr {
                    pylist.append(Claim(item.clone()).to_object(py)).unwrap();
                }
                pylist.to_object(py)
            }
            serde_json::Value::Object(obj) => {
                let dict = PyDict::new_bound(py);
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
            serde_json::Value::Bool(b) => PyBool::new_bound(py, *b).to_object(py),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i.to_object(py)
                } else if let Some(f) = n.as_f64() {
                    PyFloat::new_bound(py, f).to_object(py)
                } else {
                    panic!("Failed to convert number to i64 or f64")
                }
            }
            serde_json::Value::String(s) => PyString::new_bound(py, s).to_object(py),
            serde_json::Value::Array(arr) => {
                let pylist = PyList::empty_bound(py);
                for item in arr {
                    pylist.append(Claim(item.clone()).to_object(py)).unwrap();
                }
                pylist.to_object(py)
            }
            serde_json::Value::Object(obj) => {
                let dict = PyDict::new_bound(py);
                for (k, v) in obj {
                    dict.set_item(k, Claim(v.clone()).to_object(py)).unwrap();
                }
                dict.to_object(py)
            }
        }
    }
}
