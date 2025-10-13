import pytest # need pip install pytest
from intersection_algorithm import Rectangle, check_intersection


algorithms = ['A', 'B', 'C', 'D', 'E', 'F']

# 测试数据：前4个参数构建第一个矩形，接下来4个参数构建第二个矩形，最后1个是期望结果
test_cases = [
    # (x1, y1, width1, height1, x2, y2, width2, height2, expected)
    (0, 0, 2, 2, 1, 1, 2, 2, True),   # example, 重叠
]


# 参数化测试
@pytest.mark.parametrize("algorithm_id", algorithms)
@pytest.mark.parametrize("x1,y1,w1,h1,x2,y2,w2,h2,expected", test_cases)
def test_each_algorithm_separately(algorithm_id, x1, y1, w1, h1, x2, y2, w2, h2, expected):
    rect1 = Rectangle(x1, y1, w1, h1)
    rect2 = Rectangle(x2, y2, w2, h2)
    
    result = check_intersection(rect1, rect2, algorithm_id)
    assert result == expected, f"Algorithm {algorithm_id} failed for rectangles ({x1},{y1},{w1},{h1}) and ({x2},{y2},{w2},{h2}). Expected {expected}, got {result}"
